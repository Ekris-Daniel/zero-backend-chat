import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox


class DiscordDBManager(tk.Toplevel):
    """
    Discord-side database/relay manager.

    Manages messages stored in the configured Discord channel.

    It does NOT delete the application's local SQLite database.

    Required:
        file_share_manager

    The manager must expose:
        file_share_manager.discord
        file_share_manager.channel_id
    """

    def __init__(self, parent, file_share_manager):
        super().__init__(parent)

        self.parent = parent
        self.file_share = file_share_manager
        self.discord = file_share_manager.discord
        self.channel_id = str(
            file_share_manager.channel_id
        )

        self.messages = []
        self.loading = False
        self.deleting = False

        self.title("Discord DB Manager")
        self.geometry("1050x650")
        self.minsize(850, 500)

        self._build_ui()

        self.protocol(
            "WM_DELETE_WINDOW",
            self.destroy,
        )

        self.after(
            100,
            self.refresh,
        )

    # =====================================================
    # UI
    # =====================================================

    def _build_ui(self):

        top = ttk.Frame(self)
        top.pack(
            fill="x",
            padx=10,
            pady=10,
        )

        ttk.Label(
            top,
            text="Discord Relay Database",
            font=("Segoe UI", 15, "bold"),
        ).pack(
            side="left",
        )

        self.stats_label = ttk.Label(
            top,
            text="Loading...",
        )

        self.stats_label.pack(
            side="right",
        )

        # -------------------------------------------------
        # Controls
        # -------------------------------------------------

        controls = ttk.Frame(self)
        controls.pack(
            fill="x",
            padx=10,
            pady=(0, 8),
        )

        self.refresh_button = ttk.Button(
            controls,
            text="Refresh",
            command=self.refresh,
        )

        self.refresh_button.pack(
            side="left",
            padx=(0, 5),
        )

        self.select_all_button = ttk.Button(
            controls,
            text="Select All",
            command=self.select_all,
        )

        self.select_all_button.pack(
            side="left",
            padx=5,
        )

        self.clear_selection_button = ttk.Button(
            controls,
            text="Clear Selection",
            command=self.clear_selection,
        )

        self.clear_selection_button.pack(
            side="left",
            padx=5,
        )

        self.delete_button = ttk.Button(
            controls,
            text="Delete Selected",
            command=self.delete_selected,
        )

        self.delete_button.pack(
            side="left",
            padx=5,
        )

        self.clear_all_button = ttk.Button(
            controls,
            text="Delete Everything",
            command=self.delete_everything,
        )

        self.clear_all_button.pack(
            side="right",
        )

        # -------------------------------------------------
        # Progress
        # -------------------------------------------------

        progress_frame = ttk.Frame(self)
        progress_frame.pack(
            fill="x",
            padx=10,
            pady=(0, 8),
        )

        self.progress = ttk.Progressbar(
            progress_frame,
            mode="determinate",
        )

        self.progress.pack(
            fill="x",
            side="left",
            expand=True,
        )

        self.progress_label = ttk.Label(
            progress_frame,
            text="",
            width=25,
        )

        self.progress_label.pack(
            side="left",
            padx=(10, 0),
        )

        # -------------------------------------------------
        # Table
        # -------------------------------------------------

        table_frame = ttk.Frame(self)
        table_frame.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10),
        )

        columns = (
            "selected",
            "id",
            "author",
            "date",
            "type",
            "size",
            "content",
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="extended",
        )

        self.tree.heading(
            "selected",
            text="✓",
        )

        self.tree.heading(
            "id",
            text="Message ID",
        )

        self.tree.heading(
            "author",
            text="Author",
        )

        self.tree.heading(
            "date",
            text="Date",
        )

        self.tree.heading(
            "type",
            text="Type",
        )

        self.tree.heading(
            "size",
            text="Attachments",
        )

        self.tree.heading(
            "content",
            text="Content",
        )

        self.tree.column(
            "selected",
            width=45,
            anchor="center",
        )

        self.tree.column(
            "id",
            width=180,
        )

        self.tree.column(
            "author",
            width=130,
        )

        self.tree.column(
            "date",
            width=150,
        )

        self.tree.column(
            "type",
            width=100,
        )

        self.tree.column(
            "size",
            width=80,
            anchor="center",
        )

        self.tree.column(
            "content",
            width=350,
        )

        yscroll = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview,
        )

        xscroll = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=self.tree.xview,
        )

        self.tree.configure(
            yscrollcommand=yscroll.set,
            xscrollcommand=xscroll.set,
        )

        self.tree.grid(
            row=0,
            column=0,
            sticky="nsew",
        )

        yscroll.grid(
            row=0,
            column=1,
            sticky="ns",
        )

        xscroll.grid(
            row=1,
            column=0,
            sticky="ew",
        )

        table_frame.rowconfigure(
            0,
            weight=1,
        )

        table_frame.columnconfigure(
            0,
            weight=1,
        )

        # Double-click toggles selection.
        self.tree.bind(
            "<Double-1>",
            self.toggle_row,
        )

    # =====================================================
    # MESSAGE HELPERS
    # =====================================================

    @staticmethod
    def message_type(message):

        content = message.get(
            "content",
            "",
        )

        attachments = message.get(
            "attachments",
            [],
        )

        if content.startswith("E2EM1:"):
            return "Manifest"

        if content.startswith("E2EF1:"):
            return "File Chunk"

        if attachments:
            return "Attachment"

        return "Chat"

    @staticmethod
    def attachment_size(message):

        attachments = message.get(
            "attachments",
            [],
        )

        total = 0

        for attachment in attachments:

            try:
                total += int(
                    attachment.get(
                        "size",
                        0,
                    )
                )
            except Exception:
                pass

        if total == 0:
            return "-"

        if total < 1024:
            return f"{total} B"

        if total < 1024 * 1024:
            return f"{total / 1024:.1f} KB"

        return f"{total / (1024 * 1024):.1f} MB"

    @staticmethod
    def short_content(message):

        content = (
            message.get(
                "content",
                "",
            )
            or ""
        )

        content = content.replace(
            "\n",
            " ",
        )

        if len(content) > 70:
            return content[:67] + "..."

        return content

    # =====================================================
    # REFRESH
    # =====================================================

    def refresh(self):

        if self.loading or self.deleting:
            return

        self.loading = True

        self._set_controls(False)

        self.stats_label.config(
            text="Scanning Discord..."
        )

        self.progress["value"] = 0

        thread = threading.Thread(
            target=self._load_worker,
            daemon=True,
        )

        thread.start()

    def _load_worker(self):

        messages = []

        before = None

        try:

            while True:

                page = self.discord.get_messages(
                    self.channel_id,
                    limit=100,
                    before=before,
                )

                if not page:
                    break

                messages.extend(page)

                oldest = page[-1].get(
                    "id"
                )

                if not oldest:
                    break

                before = oldest

                if len(page) < 100:
                    break

            self.after(
                0,
                lambda: self._load_finished(
                    messages
                ),
            )

        except Exception as error:

            self.after(
                0,
                lambda: self._load_failed(
                    error
                ),
            )

    def _load_finished(self, messages):

        self.loading = False

        self.messages = messages

        for item in self.tree.get_children():
            self.tree.delete(item)

        # Show oldest -> newest.
        display_messages = list(
            reversed(messages)
        )

        for message in display_messages:

            message_id = message.get(
                "id",
                "",
            )

            author = message.get(
                "author",
                {},
            )

            author_name = author.get(
                "global_name"
            ) or author.get(
                "username",
                "Unknown",
            )

            timestamp = message.get(
                "timestamp",
                "",
            )

            self.tree.insert(
                "",
                "end",
                iid=str(message_id),
                values=(
                    "☐",
                    message_id,
                    author_name,
                    timestamp[:19],
                    self.message_type(message),
                    self.attachment_size(message),
                    self.short_content(message),
                ),
            )

        self.stats_label.config(
            text=(
                f"{len(messages)} messages "
                f"on Discord"
            ),
        )

        self.progress["value"] = 100

        self._set_controls(True)

    def _load_failed(self, error):

        self.loading = False

        self.stats_label.config(
            text="Failed to load",
        )

        self._set_controls(True)

        messagebox.showerror(
            "Discord DB Manager",
            str(error),
            parent=self,
        )

    # =====================================================
    # SELECTION
    # =====================================================

    def toggle_row(self, event):

        item = self.tree.identify_row(
            event.y
        )

        if not item:
            return

        values = list(
            self.tree.item(
                item,
                "values",
            )
        )

        if values[0] == "☐":
            values[0] = "☑"
        else:
            values[0] = "☐"

        self.tree.item(
            item,
            values=values,
        )

    def select_all(self):

        for item in self.tree.get_children():

            values = list(
                self.tree.item(
                    item,
                    "values",
                )
            )

            values[0] = "☑"

            self.tree.item(
                item,
                values=values,
            )

    def clear_selection(self):

        for item in self.tree.get_children():

            values = list(
                self.tree.item(
                    item,
                    "values",
                )
            )

            values[0] = "☐"

            self.tree.item(
                item,
                values=values,
            )

    def selected_ids(self):

        selected = []

        for item in self.tree.get_children():

            values = self.tree.item(
                item,
                "values",
            )

            if values and values[0] == "☑":

                selected.append(
                    str(values[1])
                )

        return selected

    # =====================================================
    # DELETE SELECTED
    # =====================================================

    def delete_selected(self):

        ids = self.selected_ids()

        if not ids:
            messagebox.showinfo(
                "Delete",
                "Select at least one message.",
                parent=self,
            )
            return

        confirmed = messagebox.askyesno(
            "Delete Messages",
            (
                f"Delete {len(ids)} selected "
                "Discord message(s)?\n\n"
                "This cannot be undone."
            ),
            icon="warning",
            parent=self,
        )

        if not confirmed:
            return

        self.deleting = True
        self._set_controls(False)

        threading.Thread(
            target=self._delete_worker,
            args=(ids,),
            daemon=True,
        ).start()

    def _delete_worker(self, ids):

        deleted = 0

        try:

            for message_id in ids:

                while True:

                    try:

                        self.discord.delete_message(
                            self.channel_id,
                            message_id,
                        )

                        deleted += 1

                        self.after(
                            0,
                            lambda count=deleted: (
                                self._delete_progress(
                                    count,
                                    len(ids),
                                )
                            ),
                        )

                        break

                    except Exception as error:

                        status = getattr(
                            error,
                            "status",
                            0,
                        )

                        retry_after = getattr(
                            error,
                            "retry_after",
                            0,
                        )

                        if status == 404:
                            deleted += 1
                            break

                        if status == 429:

                            if retry_after:
                                time.sleep(
                                    retry_after
                                )

                            continue

                        raise

            self.after(
                0,
                self._delete_finished,
            )

        except Exception as error:

            self.after(
                0,
                lambda: self._delete_failed(
                    error
                ),
            )

    def _delete_progress(
        self,
        current,
        total,
    ):

        self.progress["maximum"] = max(
            total,
            1,
        )

        self.progress["value"] = current

        self.progress_label.config(
            text=f"{current} / {total}"
        )

    def _delete_finished(self):

        self.deleting = False

        self.progress_label.config(
            text="Done",
        )

        self._set_controls(True)

        self.refresh()

        messagebox.showinfo(
            "Delete Complete",
            "Selected Discord messages were deleted.",
            parent=self,
        )

    def _delete_failed(self, error):

        self.deleting = False

        self._set_controls(True)

        messagebox.showerror(
            "Delete Failed",
            str(error),
            parent=self,
        )

    # =====================================================
    # DELETE EVERYTHING
    # =====================================================

    def delete_everything(self):

        confirmed = messagebox.askyesno(
            "DELETE EVERYTHING",
            (
                "This will delete EVERY accessible "
                "message from the Discord channel.\n\n"
                "That includes:\n"
                "• Normal chat messages\n"
                "• File chunks\n"
                "• File manifests\n"
                "• Attachments\n"
                "• Everything else the bot can delete\n\n"
                "Your local SQLite database will NOT "
                "be deleted.\n\n"
                "This operation cannot be undone.\n\n"
                "Continue?"
            ),
            icon="warning",
            parent=self,
        )

        if not confirmed:
            return

        self.deleting = True
        self._set_controls(False)

        threading.Thread(
            target=self._delete_all_worker,
            daemon=True,
        ).start()

    def _delete_all_worker(self):

        deleted = 0

        try:

            while True:

                messages = (
                    self.discord.get_messages(
                        self.channel_id,
                        limit=100,
                    )
                )

                if not messages:
                    break

                ids = []

                for message in messages:

                    message_id = message.get(
                        "id"
                    )

                    if message_id:
                        ids.append(
                            str(message_id)
                        )

                if not ids:
                    break

                # ------------------------------------------------
                # Bulk deletion where Discord permits it.
                #
                # The existing Discord client needs:
                # bulk_delete_messages(channel_id, ids)
                # ------------------------------------------------

                bulk_ids = []

                old_ids = []

                now = time.time()

                discord_epoch = (
                    1420070400000
                )

                for message_id in ids:

                    try:

                        snowflake = int(
                            message_id
                        )

                        timestamp = (
                            (
                                snowflake
                                >> 22
                            )
                            + discord_epoch
                        ) / 1000

                        age = (
                            now - timestamp
                        )

                        if age < (
                            14 * 24 * 60 * 60
                        ):
                            bulk_ids.append(
                                message_id
                            )
                        else:
                            old_ids.append(
                                message_id
                            )

                    except Exception:

                        old_ids.append(
                            message_id
                        )

                # ------------------------------------------------
                # Fast bulk deletion
                # ------------------------------------------------

                if bulk_ids:

                    try:

                        self.discord.bulk_delete_messages(
                            self.channel_id,
                            bulk_ids,
                        )

                        deleted += len(
                            bulk_ids
                        )

                    except Exception as error:

                        status = getattr(
                            error,
                            "status",
                            0,
                        )

                        retry_after = getattr(
                            error,
                            "retry_after",
                            0,
                        )

                        if status == 429:

                            if retry_after:
                                time.sleep(
                                    retry_after
                                )

                            continue

                        raise

                # ------------------------------------------------
                # Old messages require individual deletion
                # ------------------------------------------------

                for message_id in old_ids:

                    while True:

                        try:

                            self.discord.delete_message(
                                self.channel_id,
                                message_id,
                            )

                            deleted += 1

                            break

                        except Exception as error:

                            status = getattr(
                                error,
                                "status",
                                0,
                            )

                            retry_after = getattr(
                                error,
                                "retry_after",
                                0,
                            )

                            if status == 404:
                                break

                            if status == 429:

                                if retry_after:
                                    time.sleep(
                                        retry_after
                                    )

                                continue

                            raise

                self.after(
                    0,
                    lambda count=deleted: (
                        self._delete_progress(
                            count,
                            None,
                        )
                    ),
                )

            self.after(
                0,
                lambda: self._all_deleted(
                    deleted
                ),
            )

        except Exception as error:

            self.after(
                0,
                lambda: self._delete_failed(
                    error
                ),
            )

    def _all_deleted(self, deleted):

        self.deleting = False

        self._set_controls(True)

        self.progress_label.config(
            text="Complete",
        )

        self.refresh()

        messagebox.showinfo(
            "Discord Cleared",
            (
                f"Deleted {deleted} "
                "Discord messages.\n\n"
                "Local SQLite data was left untouched."
            ),
            parent=self,
        )

    # =====================================================
    # GUI STATE
    # =====================================================

    def _set_controls(self, enabled):

        state = (
            "normal"
            if enabled
            else "disabled"
        )

        self.refresh_button.config(
            state=state,
        )

        self.select_all_button.config(
            state=state,
        )

        self.clear_selection_button.config(
            state=state,
        )

        self.delete_button.config(
            state=state,
        )

        self.clear_all_button.config(
            state=state,
        )