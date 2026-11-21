import os
import random
import webbrowser
import tkinter as tk
from tkinter import filedialog

# Danh sách các đoạn mã nguồn C thực tế được cắt nhỏ ra để giả lập gõ phím
CODE_SNIPPETS = [
    """struct group_info init_groups = { .usage = ATOMIC_INIT(2) };

struct group_info *groups_alloc(int gidsetsize){
	struct group_info *group_info;
	int nblocks;
	int i;

	nblocks = (gidsetsize + NGROUPS_PER_BLOCK - 1) / NGROUPS_PER_BLOCK;
	nblocks = nblocks ? : 1;
	group_info = kmalloc(sizeof(*group_info) + nblocks*sizeof(gid_t *), GFP_USER);
	if (!group_info)
		return NULL;
	group_info->ngroups = gidsetsize;
	group_info->nblocks = nblocks;
	atomic_set(&group_info->usage, 1);

	if (gidsetsize <= NGROUPS_SMALL)
		group_info->blocks[0] = group_info->small_block;
	else {
		for (i = 0; i < nblocks; i++) {
			gid_t *b;
			b = (void *)__get_free_page(GFP_USER);
			if (!b)
				goto out_undo_partial_alloc;
			group_info->blocks[i] = b;
		}
	}
	return group_info;

out_undo_partial_alloc:
	while (--i >= 0) {
		free_page((unsigned long)group_info->blocks[i]);
	}
	kfree(group_info);
	return NULL;
}""",
    """EXPORT_SYMBOL(groups_alloc);

void groups_free(struct group_info *group_info)
{
	if (group_info->blocks[0] != group_info->small_block) {
		int i;
		for (i = 0; i < group_info->nblocks; i++)
			free_page((unsigned long)group_info->blocks[i]);
	}
	kfree(group_info);
}

EXPORT_SYMBOL(groups_free);""",
    """static int groups_to_user(gid_t __user *grouplist,
			  const struct group_info *group_info)
{
	int i;
	unsigned int count = group_info->ngroups;

	for (i = 0; i < group_info->nblocks; i++) {
		unsigned int cp_count = min(NGROUPS_PER_BLOCK, count);
		unsigned int len = cp_count * sizeof(*grouplist);

		if (copy_to_user(grouplist, group_info->blocks[i], len))
			return -EFAULT;

		grouplist += NGROUPS_PER_BLOCK;
		count -= cp_count;
	}
	return 0;
}""",
    """static int groups_from_user(struct group_info *group_info,
    gid_t __user *grouplist)
{
	int i;
	unsigned int count = group_info->ngroups;

	for (i = 0; i < group_info->nblocks; i++) {
		unsigned int cp_count = min(NGROUPS_PER_BLOCK, count);
		unsigned int len = cp_count * sizeof(*grouplist);

		if (copy_from_user(group_info->blocks[i], grouplist, len))
			return -EFAULT;

		grouplist += NGROUPS_PER_BLOCK;
		count -= cp_count;
	}
	return 0;
}""",
    """static void groups_sort(struct group_info *group_info)
{
	int base, max, stride;
	int gidsetsize = group_info->ngroups;

	for (stride = 1; stride < gidsetsize; stride = 3 * stride + 1)
		; /* nothing */
	stride /= 3;

	while (stride) {
		max = gidsetsize - stride;
		for (base = 0; base < max; base++) {
			int left = base;
			int right = left + stride;
			gid_t tmp = GROUP_AT(group_info, right);

			while (left >= 0 && GROUP_AT(group_info, left) > tmp) {
				GROUP_AT(group_info, right) =
				    GROUP_AT(group_info, left);
				right = left;
				left -= stride;
			}
			GROUP_AT(group_info, right) = tmp;
		}
		stride /= 3;
	}
}""",
    """int groups_search(const struct group_info *group_info, gid_t grp)
{
	unsigned int left, right;

	if (!group_info)
		return 0;

	left = 0;
	right = group_info->ngroups;
	while (left < right) {
		unsigned int mid = left + (right - left)/2;
		if (grp > GROUP_AT(group_info, mid))
			left = mid + 1;
		else if (grp < GROUP_AT(group_info, mid))
			right = mid;
		else
			return 1;
	}
	return 0;
}""",
    """int set_groups(struct cred *new, struct group_info *group_info)
{
	put_group_info(new->group_info);
	groups_sort(group_info);
	get_group_info(group_info);
	new->group_info = group_info;
	return 0;
}

EXPORT_SYMBOL(set_groups);

int set_current_groups(struct group_info *group_info)
{
	struct cred *new;
	int ret;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	ret = set_groups(new, group_info);
	if (ret < 0) {
		abort_creds(new);
		return ret;
	}

	return commit_creds(new);
}

EXPORT_SYMBOL(set_current_groups);""",
    """SYSCALL_DEFINE2(getgroups, int, gidsetsize, gid_t __user *, grouplist)
{
	const struct cred *cred = current_cred();
	int i;

	if (gidsetsize < 0)
		return -EINVAL;

	i = cred->group_info->ngroups;
	if (gidsetsize) {
		if (i > gidsetsize) {
			i = -EINVAL;
			goto out;
		}
		if (groups_to_user(grouplist, cred->group_info)) {
			i = -EFAULT;
			goto out;
		}
	}
out:
	return i;
}""",
    """SYSCALL_DEFINE2(setgroups, int, gidsetsize, gid_t __user *, grouplist)
{
	struct group_info *group_info;
	int retval;

	if (!nsown_capable(CAP_SETGID))
		return -EPERM;
	if ((unsigned)gidsetsize > NGROUPS_MAX)
		return -EINVAL;

	group_info = groups_alloc(gidsetsize);
	if (!group_info)
		return -ENOMEM;
	retval = groups_from_user(group_info, grouplist);
	if (retval) {
		put_group_info(group_info);
		return retval;
	}

	retval = set_current_groups(group_info);
	put_group_info(group_info);

	return retval;
}

int in_group_p(gid_t grp)
{
	const struct cred *cred = current_cred();
	int retval = 1;

	if (grp != cred->fsgid)
		retval = groups_search(cred->group_info, grp);
	return retval;
}

EXPORT_SYMBOL(in_group_p);

int in_egroup_p(gid_t grp)
{
	const struct cred *cred = current_cred();
	int retval = 1;

	if (grp != cred->egid)
		retval = groups_search(cred->group_info, grp);
	return retval;
}""",
]


class TerminalApp:

  def __init__(self, root):
    self.root = root
    self.root.title("Terminal")
    self.root.state("zoomed")
    self.root.configure(bg="black")

    self.is_fullscreen = False
    self.root.bind("<F11>", self.toggle_fullscreen)

    self.mode = "text"
    self.user_text = ""
    self.image_path = None
    self.current_snippet = random.choice(CODE_SNIPPETS)
    self.char_index = 0
    self.is_terminal_active = False

    self.create_setup_ui()

  def create_setup_ui(self):
    self.center_frame = tk.Frame(self.root, bg="black")
    self.center_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    self.setup_box = tk.Frame(
        self.center_frame,
        bg="#050505",
        bd=1,
        relief="solid",
        highlightbackground="#00ff00",
        highlightthickness=1,
    )
    self.setup_box.pack(padx=20, pady=20)

    self.step1_frame = tk.Frame(self.setup_box, bg="#050505")
    self.step1_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

    tk.Label(
        self.step1_frame,
        text="1. Select input type:",
        bg="#050505",
        fg="#00ff00",
        font=("Consolas", 12, "bold"),
    ).pack(anchor="w", pady=5)

    self.mode_var = tk.StringVar(value="text")
    mode_menu = tk.OptionMenu(
        self.step1_frame, self.mode_var, "text", "image", "both"
    )
    mode_menu.config(bg="#111111", fg="#00ff00", font=("Consolas", 10), width=15)
    mode_menu.pack(anchor="w", pady=5)

    tk.Button(
        self.step1_frame,
        text="Continue",
        bg="#00ff00",
        fg="black",
        font=("Consolas", 10, "bold"),
        command=self.go_to_step2,
    ).pack(anchor="w", pady=10)

    self.step2_frame = tk.Frame(self.setup_box, bg="#050505")

  def toggle_fullscreen(self, event=None):
    self.is_fullscreen = not self.is_fullscreen
    self.root.attributes("-fullscreen", self.is_fullscreen)
    return "break"

  def go_to_step2(self):
    self.mode = self.mode_var.get()

    self.step1_frame.pack_forget()
    self.step2_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

    if self.mode in ["text", "both"]:
      tk.Label(
          self.step2_frame,
          text="Enter text:",
          bg="#050505",
          fg="#00ff00",
          font=("Consolas", 11),
      ).pack(anchor="w", pady=2)
      self.text_entry = tk.Entry(
          self.step2_frame,
          bg="#111111",
          fg="#00ff00",
          font=("Consolas", 11),
          width=30,
          insertbackground="#00ff00",
      )
      self.text_entry.pack(anchor="w", pady=5)
      self.text_entry.focus_set()

    if self.mode in ["image", "both"]:
      tk.Label(
          self.step2_frame,
          text="Upload image:",
          bg="#050505",
          fg="#00ff00",
          font=("Consolas", 11),
      ).pack(anchor="w", pady=2)
      self.img_pick_btn = tk.Button(
          self.step2_frame,
          text="Choose image file...",
          bg="#111111",
          fg="#00ff00",
          font=("Consolas", 10),
          command=self.pick_image,
      )
      self.img_pick_btn.pack(anchor="w", pady=5)
      self.img_lbl_status = tk.Label(
          self.step2_frame,
          text="No image selected",
          bg="#050505",
          fg="gray",
          font=("Consolas", 9),
      )
      self.img_lbl_status.pack(anchor="w", pady=2)

    tk.Button(
        self.step2_frame,
        text="Start Terminal",
        bg="#00ff00",
        fg="black",
        font=("Consolas", 10, "bold"),
        command=self.start_terminal,
    ).pack(anchor="w", pady=15)

  def pick_image(self):
    path = filedialog.askopenfilename(
        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")]
    )
    if path:
      self.image_path = os.path.abspath(path)
      self.img_lbl_status.config(
          text=f"Selected: {self.image_path}", fg="#00ff00"
      )

  def start_terminal(self):
    if self.mode in ["text", "both"]:
      self.user_text = self.text_entry.get()

    if hasattr(self, "center_frame") and self.center_frame:
      self.center_frame.destroy()

    self.terminal_text = tk.Text(
        self.root,
        bg="black",
        fg="#00ff00",
        font=("Consolas", 14),
        insertbackground="#00ff00",
        bd=0,
        highlightthickness=0,
        cursor="arrow",
    )
    self.terminal_text.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)
    self.terminal_text.focus_set()

    self.is_terminal_active = True
    self.terminal_text.bind("<Key>", self.handle_key)

  def handle_key(self, event):
    if not self.is_terminal_active:
      if event.keysym == "F11":
        self.toggle_fullscreen()
      return "break"

    if event.keysym == "F11":
      self.toggle_fullscreen()
      return "break"

    if event.keysym == "Return":
      self.is_terminal_active = False
      self.show_output()
      return "break"

    if event.keysym in [
        "BackSpace",
        "Delete",
        "Left",
        "Right",
        "Up",
        "Down",
        "Home",
        "End",
        "Shift_L",
        "Shift_R",
        "Control_L",
        "Control_R",
        "Alt_L",
        "Alt_R",
        "Caps_Lock",
        "Tab",
    ]:
      return "break"

    chars_to_add = self.current_snippet[
        self.char_index : self.char_index + 3
    ]
    self.char_index += 3

    if self.char_index >= len(self.current_snippet):
      self.char_index = 0

    self.terminal_text.insert(tk.END, chars_to_add)
    self.terminal_text.see(tk.END)

    return "break"

  def show_output(self):
    output_str = "\n\noutput = "
    if self.mode == "text":
      output_str += self.user_text
      self.terminal_text.insert(tk.END, output_str)
    elif self.mode == "image":
      self.terminal_text.insert(tk.END, output_str)
      if self.image_path:
        self.add_image_button()
      else:
        self.terminal_text.insert(tk.END, "[No image selected]")
    elif self.mode == "both":
      self.terminal_text.insert(tk.END, output_str + self.user_text + " ")
      if self.image_path:
        self.add_image_button()

    self.terminal_text.see(tk.END)

  def add_image_button(self):
    self.terminal_text.insert(tk.END, "image", ("hyperlink",))
    self.terminal_text.tag_config(
        "hyperlink", foreground="#00ffff", underline=True
    )
    self.terminal_text.tag_bind(
        "hyperlink", "<Button-1>", lambda e: self.open_image()
    )
    self.terminal_text.tag_bind(
        "hyperlink",
        "<Enter>",
        lambda e: self.terminal_text.config(cursor="hand2"),
    )
    self.terminal_text.tag_bind(
        "hyperlink",
        "<Leave>",
        lambda e: self.terminal_text.config(cursor="arrow"),
    )

  def open_image(self):
    if self.image_path and os.path.exists(self.image_path):
      try:
        webbrowser.open(self.image_path)
      except Exception as e:
        self.terminal_text.insert(tk.END, f"\n[Error opening image: {e}]")


if __name__ == "__main__":
  root = tk.Tk()
  app = TerminalApp(root)
  root.mainloop()