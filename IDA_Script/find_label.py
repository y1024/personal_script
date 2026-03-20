# -*- coding: utf-8 -*-
import idaapi
import idc

ACTION_FWD = "jl:search_label_forward"
ACTION_BWD = "jl:search_label_backward"
TOP_MENU_NAME = "搜索label"

def find_next_label(ea: int, forward: bool) -> int:
    cur = ea
    while True:
        if forward:
            cur = idc.next_head(cur)
            if cur == idaapi.BADADDR:
                return idaapi.BADADDR
        else:
            cur = idc.prev_head(cur)
            if cur == idaapi.BADADDR:
                return idaapi.BADADDR
        name = idc.get_name(cur, idc.GN_VISIBLE)
        if name:
            return cur
    return idaapi.BADADDR

class SearchLabelForwardHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        tgt = find_next_label(ea, forward=True)
        print(f"forward {ea:08x} {tgt:08x}")
        if tgt != idaapi.BADADDR:
            idaapi.jumpto(tgt)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class SearchLabelBackwardHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        tgt = find_next_label(ea, forward=False)
        print(f"backward {ea:08x} {tgt:08x}")
        if tgt != idaapi.BADADDR:
            idaapi.jumpto(tgt)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class PopupHook(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) != idaapi.BWN_DISASM:
            return
        idaapi.create_menu(TOP_MENU_NAME, TOP_MENU_NAME, "Edit/")
        idaapi.attach_action_to_popup(widget, popup, ACTION_BWD, f"{TOP_MENU_NAME}/")
        idaapi.attach_action_to_popup(widget, popup, ACTION_FWD, f"{TOP_MENU_NAME}/")

class SearchLabelPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Add popup menu to search next/prev label"
    help = ""
    wanted_name = "Search Label Popup"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self.hook = None

    def init(self):
        idaapi.register_action(idaapi.action_desc_t(
            ACTION_BWD, "向上搜索label", SearchLabelBackwardHandler(), None, "Search previous label", 0
        ))
        idaapi.register_action(idaapi.action_desc_t(
            ACTION_FWD, "向下搜索label", SearchLabelForwardHandler(), None, "Search next label", 0
        ))
        self.hook = PopupHook()
        self.hook.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.hook:
            self.hook.unhook()
            self.hook = None

def PLUGIN_ENTRY():
    return SearchLabelPlugin()

