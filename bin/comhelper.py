import os
import sys
import locale
import subprocess
import pythoncom
import idaapi
import idautils
import idc

invokekinds = {
    pythoncom.INVOKE_FUNC: "func",
    pythoncom.INVOKE_PROPERTYGET: "get",
    pythoncom.INVOKE_PROPERTYPUT: "put",
    pythoncom.INVOKE_PROPERTYPUTREF: "put_ref",
}

vartypes = {
    pythoncom.VT_EMPTY: "Empty",
    pythoncom.VT_NULL: "NULL",
    pythoncom.VT_I2: "Integer_2",
    pythoncom.VT_I4: "Integer_4",
    pythoncom.VT_R4: "Real_4",
    pythoncom.VT_R8: "Real_8",
    pythoncom.VT_CY: "CY",
    pythoncom.VT_DATE: "Date",
    pythoncom.VT_BSTR: "String",
    pythoncom.VT_DISPATCH: "IDispatch",
    pythoncom.VT_ERROR: "Error",
    pythoncom.VT_BOOL: "BOOL",
    pythoncom.VT_VARIANT: "Variant",
    pythoncom.VT_UNKNOWN: "IUnknown",
    pythoncom.VT_DECIMAL: "Decimal",
    pythoncom.VT_I1: "Integer_1",
    pythoncom.VT_UI1: "Unsigned_integer_1",
    pythoncom.VT_UI2: "Unsigned_integer_2",
    pythoncom.VT_UI4: "Unsigned_integer_4",
    pythoncom.VT_I8: "Integer_8",
    pythoncom.VT_UI8: "Unsigned_integer_8",
    pythoncom.VT_INT: "Integer",
    pythoncom.VT_UINT: "Unsigned_integer",
    pythoncom.VT_VOID: "Void",
    pythoncom.VT_HRESULT: "HRESULT",
    pythoncom.VT_PTR: "Pointer",
    pythoncom.VT_SAFEARRAY: "SafeArray",
    pythoncom.VT_CARRAY: "C_Array",
    pythoncom.VT_USERDEFINED: "User_Defined",
    pythoncom.VT_LPSTR: "Pointer_to_string",
    pythoncom.VT_LPWSTR: "Pointer_to_Wide_String",
    pythoncom.VT_FILETIME: "File_time",
    pythoncom.VT_BLOB: "Blob",
    pythoncom.VT_STREAM: "IStream",
    pythoncom.VT_STORAGE: "IStorage",
    pythoncom.VT_STORED_OBJECT: "Stored_object",
    pythoncom.VT_STREAMED_OBJECT: "Streamed_object",
    pythoncom.VT_BLOB_OBJECT: "Blob_object",
    pythoncom.VT_CF: "CF",
    pythoncom.VT_CLSID: "CLSID",
}

type_flags = [
    (pythoncom.VT_VECTOR, "Vector"),
    (pythoncom.VT_ARRAY, "Array"),
    (pythoncom.VT_BYREF, "ByRef"),
    (pythoncom.VT_RESERVED, "Reserved"),
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
p_initialized = False


class ComHelperResultChooser(idaapi.Choose2):
    def __init__(self,
                 title,
                 items,
                 flags=0,
                 width=None,
                 height=None,
                 embedded=False,
                 modal=False):
        idaapi.Choose2.__init__(
            self,
            title, [
                ["Address", idaapi.Choose2.CHCOL_HEX | 10],
                ["Function", idaapi.Choose2.CHCOL_PLAIN | 25],
                ["Parent", idaapi.Choose2.CHCOL_PLAIN | 25],
                ["Desc", idaapi.Choose2.CHCOL_PLAIN | 40],
            ],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded)
        self.items = items
        self.selcount = 0
        self.n = len(items)

    def OnClose(self):
        return

    def OnSelectLine(self, n):
        self.selcount += 1
        idc.Jump(self.items[n][0])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [idc.atoa(res[0]), res[1], res[2], res[3]]
        return res

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show() >= 0


#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class Comhelper_Plugin_t(idaapi.plugin_t):
    comment = "Comhelper plugin for IDA Pro"
    help = "Comhelper"
    wanted_name = "Comhelper"
    wanted_hotkey = "Shift-Alt-C"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global p_initialized
        if p_initialized is False:
            p_initialized = True
            idaapi.register_action(
                idaapi.action_desc_t("Comhelper", "Comhelper", self.search,
                                     None, None, 0))
            print("=" * 80)
            print("Comhelper search shortcut key is " + self.wanted_hotkey)
            print("=" * 80)

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def get_com_vas(self, dllpath, clsid, iid, count):
        if idaapi.get_inf_structure().is_64bit():
            toolname = 'comfinder_x64.exe'
        else:
            toolname = 'comfinder_x86.exe'
        toolpath = os.path.join(BASE_DIR, toolname)
        try:
            ret = subprocess.check_output(
                [toolpath, dllpath, clsid, iid, count], shell=True)
        except subprocess.CalledProcessError, e:
            return [
                'LoadDll fail', 'GetProc fail', 'GetClass fail',
                'CreateInstance fail'
            ][e.returncode - 1] + ' for clsid:{} iid:{}'.format(clsid,iid)
        vas = []
        imagebase = ida_nalt.get_imagebase()

        for rvahex in ret.split('\n'):
            rvahex = rvahex.strip()
            if rvahex:
                vas.append(int(rvahex, 16) + imagebase)
        return vas

    def search(self):

        exports = set([info[3] for info in idautils.Entries()])
        comexports = set([
            'DllUnregisterServer', 'DllEntryPoint', 'DllGetClassObject',
            'DllCanUnloadNow', 'DllRegisterServer'
        ])
        dllpath = ida_nalt.get_input_file_path().decode('utf-8')
        if not comexports.issubset(exports):
            print('{} is not COM! exports mismatching'.format(dllpath))
            return
        try:
            tlb = pythoncom.LoadTypeLib(dllpath)
        except:
            print('{} is not COM! LoadTypeLib fail'.format(dllpath))
            return
        classes = {}
        values = []
        for i in range(tlb.GetTypeInfoCount()):
            if tlb.GetTypeInfoType(i) == pythoncom.TKIND_COCLASS:
                ctypeinfo = tlb.GetTypeInfo(i)
                clsid = str(ctypeinfo.GetTypeAttr().iid)
                for j in range(ctypeinfo.GetTypeAttr().cImplTypes):
                    typeinfo = ctypeinfo.GetRefTypeInfo(
                        ctypeinfo.GetRefTypeOfImplType(j))
                    attr = typeinfo.GetTypeAttr()
                    name = tlb.GetDocumentation(i)[0]
                    iid = str(attr.iid)
                    vas = self.get_com_vas(
                        dllpath.encode(locale.getdefaultlocale()[1]), clsid,
                        iid, str(attr.cFuncs))
                    if isinstance(vas, str):
                        print(vas)
                    else:
                        for findex in range(attr.cFuncs):
                            fundesc = typeinfo.GetFuncDesc(findex)
                            funnames = typeinfo.GetNames(fundesc.memid)
                            funname_ext = "{}_{}_{}".format(
                                name, funnames[0],
                                invokekinds[fundesc.invkind])
                            typ, flags, default = fundesc.rettype
                            desc = ''
                            if fundesc.invkind == pythoncom.INVOKE_FUNC:
                                desc += vartypes.get(typ, 'UNKNOWN') + ' ('
                                argi = 1
                                for argdesc in fundesc.args:
                                    typ, flags, default = argdesc
                                    desc += '{} {}'.format(
                                        vartypes.get(typ, 'UNKNOWN'),
                                        funnames[argi])
                                    if default is not None:
                                        desc += '={}'.format(default)
                                    desc += ' ,'
                                    argi += 1
                                desc += ')'
                            idaapi.set_name(vas[findex], funname_ext)
                            values.append(
                                [vas[findex], funname_ext, name, desc])
        ComHelperResultChooser("Comhelper", values).show()

    def run(self, arg):
        self.search()


# register IDA plugin
def PLUGIN_ENTRY():
    return Comhelper_Plugin_t()
