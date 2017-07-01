/* KeeChallenge--Provides Yubikey challenge-response capability to Keepass
*  Copyright (C) 2014  Ben Rush
*
*  This program is free software; you can redistribute it and/or
*  modify it under the terms of the GNU General Public License
*  as published by the Free Software Foundation; either version 2
*  of the License, or (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

using System;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Windows.Forms;
using System.Security;
using System.Runtime.ConstrainedExecution;
using System.IO;

namespace KeeChallenge
{
    public enum YubiSlot
    {
        SLOT1 = 0,
        SLOT2 = 1
    };

    public struct SCardIORequest
    {
        public Int32 dwProtocol;
        public Int32 cbPciLength;
    };

    public class YubiWrapper
    {
        public const uint yubiRespLen = 20;
        private const uint yubiBuffLen = 64;

        private static byte[] slots = { 0x30, 0x38 };

        private IntPtr ctx = IntPtr.Zero;
        private List<string> readers = new List<string>();

        private const int SCARD_SCOPE_SYSTEM = 0x0002;

        private const int SCARD_AUTOALLOCATE = (-1);

        private const int SCARD_SHARE_SHARED    = 0x0002;
        private const int SCARD_SHARE_EXCLUSIVE = 0x0001;

        private const int SCARD_PROTOCOL_T0  = 0x0001;
        private const int SCARD_PROTOCOL_T1  = 0x0002;
        private const int SCARD_PROTOCOL_RAW = 0x0004;

        private const int SCARD_LEAVE_CARD   = 0x0000;
        private const int SCARD_RESET_CARD   = 0x0001;
        private const int SCARD_UNPOWER_CARD = 0x0002;
        private const int SCARD_EJECT_CARD   = 0x0003;

        private static bool Is64BitProcess
        {
            get
            {
                return (IntPtr.Size == 8);
            }
        }
        private static bool IsLinux
        {
            get
            {
                int p = (int)Environment.OSVersion.Platform;
                return (p == 4) || (p == 128);
            }
        }

        [DllImport("winscard.dll")]
        private static extern int SCardEstablishContext(Int32 dwScope, IntPtr pvReserved1, IntPtr pvReserved2, ref IntPtr phContext);
        [DllImport("winscard.dll")]
        private static extern int SCardReleaseContext(IntPtr hContext);

        [DllImport("winscard.dll")]
        private static extern int SCardListReaders(IntPtr hContext, IntPtr mszGroups, IntPtr mszReaders, ref Int32 pcchReaders);

        [DllImport("winscard.dll")]
        private static extern int SCardConnect(IntPtr hContext, IntPtr szReader, Int32 dwShareMode, Int32 dwPreferredProtocols, ref IntPtr phCard, ref Int32 pdwActiveProtocol);
        [DllImport("winscard.dll")]
        private static extern int SCardDisconnect(IntPtr hCard, Int32 dwDisposition);

        [DllImport("winscard.dll")]
        private static extern int SCardTransmit(IntPtr hCard, IntPtr pioSendPci, IntPtr pbSendBuffer, Int32 cbSendLength, IntPtr pioRecvPci, IntPtr pbRecvBuffer, ref Int32 pcbRecvLength);
        [DllImport("winscard.dll", EntryPoint="SCardTransmit")]
        private static extern int SCardTransmit64(IntPtr hCard, IntPtr pioSendPci, IntPtr pbSendBuffer, Int64 cbSendLength, IntPtr pioRecvPci, IntPtr pbRecvBuffer, ref Int64 pcbRecvLength);

        public bool Init()
        {
            int rc;

            rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, IntPtr.Zero, IntPtr.Zero, ref ctx);
            if (rc != 0) {
                MessageBox.Show("SCardEstablishContext failed", "Error", MessageBoxButtons.OK);
                return false;
            }

            IntPtr mszReaders = IntPtr.Zero;
            Int32 cchReaders = 0;
            rc = SCardListReaders(ctx, IntPtr.Zero, IntPtr.Zero, ref cchReaders);
            if (rc != 0) {
                MessageBox.Show("SCardListReaders failed", "Error", MessageBoxButtons.OK);
                return false;
            }
            mszReaders = Marshal.AllocHGlobal(cchReaders);
            rc = SCardListReaders(ctx, IntPtr.Zero, mszReaders, ref cchReaders);
            if (rc != 0) {
                MessageBox.Show("SCardListReaders failed", "Error", MessageBoxButtons.OK);
                return false;
            }

            IntPtr curReader = mszReaders;
            List<string> allReaders = new List<string>();
            string s = Marshal.PtrToStringAnsi(curReader);
            while (s.Length > 0) {
                curReader = new IntPtr(curReader.ToInt64() + s.Length + 1);
                allReaders.Add(s);
                s = Marshal.PtrToStringAnsi(curReader);
            }
            Marshal.FreeHGlobal(mszReaders);

            foreach (string reader in allReaders) {
                System.Console.WriteLine("Reader: {0}", reader);

                IntPtr szReader = Marshal.StringToHGlobalAnsi(reader);
                IntPtr card = IntPtr.Zero;
                Int32 activeProto = 0;

                rc = SCardConnect(ctx, szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, ref card, ref activeProto);
                if (rc != 0) {
                    System.Console.WriteLine("  SCardConnect failed with {0}", rc);
                    continue;
                }

                byte[] sendBuffer = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x00 };
                byte[] recvBuffer;

                rc = doTransmit(card, activeProto, sendBuffer, out recvBuffer);
                if (rc != 0) {
                    System.Console.WriteLine("  SCardTransmit failed with {0}", rc);
                    continue;
                }

                if (recvBuffer[recvBuffer.Length - 2] == 0x90 && recvBuffer[recvBuffer.Length - 1] == 0x00) {
                    readers.Add(reader);
                    System.Console.WriteLine("Found Yubikey OTP app on card in reader: {0}", reader);
                } else {
                    System.Console.WriteLine("  Did not respond to Yubikey OTP SELECT cmd (send {0:X} {1:X})", recvBuffer[recvBuffer.Length - 2], recvBuffer[recvBuffer.Length - 1]);
                }

                SCardDisconnect(card, SCARD_LEAVE_CARD);

                Marshal.FreeHGlobal(szReader);
            }

            if (readers.Count < 1) {
                MessageBox.Show("Could not find any Yubikey on the system", "Error", MessageBoxButtons.OK);
                return false;
            }

            return true;
        }

        private int doTransmit(IntPtr card, Int32 activeProto, byte[] sendBuffer, out byte[] recvBuffer)
        {
            SCardIORequest sendPci = new SCardIORequest();
            sendPci.dwProtocol = activeProto;
            sendPci.cbPciLength = Marshal.SizeOf(sendPci);

            IntPtr pSendPci = Marshal.AllocHGlobal(Marshal.SizeOf(sendPci));

            Marshal.StructureToPtr(sendPci, pSendPci, false);

            IntPtr pSendBuffer = Marshal.AllocHGlobal(sendBuffer.Length);
            Marshal.Copy(sendBuffer, 0, pSendBuffer, sendBuffer.Length);

            const Int32 RECV_LIMIT = 256 + 5;
            IntPtr pRecvBuffer = Marshal.AllocHGlobal((int)RECV_LIMIT);
            Int32 recvLength = RECV_LIMIT;

            int rc;
            if (Is64BitProcess && IsLinux) {
                System.Console.WriteLine("Using 64-bit pcsclite workaround");
                Int64 rxl = RECV_LIMIT;
                rc = SCardTransmit64(card, pSendPci, pSendBuffer, sendBuffer.Length, IntPtr.Zero, pRecvBuffer, ref rxl);
                recvLength = (Int32)rxl;
            } else {
                rc = SCardTransmit(card, pSendPci, pSendBuffer, sendBuffer.Length, IntPtr.Zero, pRecvBuffer, ref recvLength);
            }
            if (rc != 0) {
                recvBuffer = null;
                Marshal.FreeHGlobal(pSendPci);
                Marshal.FreeHGlobal(pSendBuffer);
                Marshal.FreeHGlobal(pRecvBuffer);
                return rc;
            }

            recvBuffer = new byte[recvLength];
            Marshal.Copy(pRecvBuffer, recvBuffer, 0, (int)recvLength);

            Marshal.FreeHGlobal(pSendPci);
            Marshal.FreeHGlobal(pSendBuffer);
            Marshal.FreeHGlobal(pRecvBuffer);
            return 0;
        }

        public bool ChallengeResponse(YubiSlot slot, byte[] challenge, out byte[] response)
        {
            long rc;

            rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, IntPtr.Zero, IntPtr.Zero, ref ctx);
            if (rc != 0) {
                throw (new Exception("SCardEstablishContext failed"));
            }

            if (readers.Count < 1) {
                throw (new Exception("No readers found"));
            }

            IntPtr szReader = Marshal.StringToHGlobalAnsi(readers[0]);
            IntPtr card = IntPtr.Zero;
            Int32 activeProto = 0;

            rc = SCardConnect(ctx, szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, ref card, ref activeProto);
            if (rc != 0) {
                throw (new Exception("SCardConnect failed"));
            }

            byte[] sendBuffer = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x00 };
            byte[] recvBuffer;

            rc = doTransmit(card, activeProto, sendBuffer, out recvBuffer);
            if (rc != 0) {
                throw (new Exception("SCardTransmit failed"));
            }

            if (recvBuffer[recvBuffer.Length - 2] != 0x90 || recvBuffer[recvBuffer.Length - 1] != 0x00) {
                throw (new Exception("Yubikey returned error on select"));
            }

            sendBuffer = new byte[challenge.Length + 6];
            sendBuffer[0] = 0x00;
            sendBuffer[1] = 0x01;
            sendBuffer[2] = slots[(int)slot];
            sendBuffer[3] = 0x00;
            sendBuffer[4] = (byte)challenge.Length;
            for (int i = 0; i < challenge.Length; ++i)
                sendBuffer[5 + i] = challenge[i];

            recvBuffer = null;
            rc = doTransmit(card, activeProto, sendBuffer, out recvBuffer);
            if (rc != 0) {
                System.Console.WriteLine("HMAC command transmit failed: {0:X}", rc);
                throw (new Exception("SCardTransmit failed"));
            }

            int respLen = recvBuffer.Length - 2;
            if (recvBuffer[respLen] != 0x90 || recvBuffer[respLen + 1] != 0x00) {
                System.Console.WriteLine("Yubikey returned failure: {0:X} {1:X}", recvBuffer[respLen], recvBuffer[respLen + 1]);
                throw (new Exception("Yubikey returned error on hmac"));
            }

            response = new byte[respLen];
            for (int i = 0; i < respLen; ++i) {
                response[i] = recvBuffer[i];
            }

            SCardDisconnect(card, SCARD_RESET_CARD);

            Marshal.FreeHGlobal(szReader);

            return true;
        }

        public void Close()
        {
            SCardReleaseContext(ctx);
        }
    }
}
