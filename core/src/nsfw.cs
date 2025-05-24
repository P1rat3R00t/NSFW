using System;
using System.Runtime.InteropServices;

public class DataWiper
{
    [DllImport("DataWiperDll.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
    public static extern bool WipeData(string targetPath, int passes);

    [DllImport("DataWiperDll.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
    public static extern bool WipeDataExtended(string targetPath, int passes);
}
