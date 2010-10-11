using System;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace MUDServer
{
	
	
	public class Client
	{
		
		public delegate void DisconnectedEventHandler(int hash, EventArgs e);
		public delegate void EstablishedEventHandler(int hash, EventArgs e);
		public delegate void AuthenticatedEventHandler(int hash, EventArgs e);
		private Socket socket;
		private int hash = 0;
		private byte[] dataBuffer = new byte[1024];
		public event DisconnectedEventHandler Disconnected;
		public event EstablishedEventHandler Established;
		public event AuthenticatedEventHandler Authenticated;
		public enum ConnectionState { Waiting, Established, Handshaking, Authenticated, Disconnected };
		public ConnectionState Status { get; private set; }
		private string remoteHandshake;
		private string ConnectionOrigin;
		private string ServerLocation = "ws://localhost:1167/test";
		private byte[] FirstByte;
		private byte[] LastByte;
		
		public Client (Socket workerSocket)
		{
			
			Status = Client.ConnectionState.Waiting;
			socket = workerSocket;
			hash = socket.GetHashCode();
			
			FirstByte = new byte[1];
			LastByte = new byte[1];
			FirstByte[0] = 0x00;
			LastByte[0] = 0xFF;
			
			this.Established += HandleEstablished;
			this.Authenticated += HandleAuthenticated;
			waitForData();
			
		}
		
		private void HandleEstablished (int hash, EventArgs e)
		{
			
		}

		private void HandleAuthenticated (int hash, EventArgs e)
		{
			
			Console.WriteLine("Authenticated");
			sendMessage("Welcome to Brent's Realm!");
			
		}
		
		public int getHash()
		{
		
			return hash;
			
		}
		
		private void waitForData() 
		{
		
			try
			{
				socket.BeginReceive (dataBuffer, 0, 
					dataBuffer.Length,
					SocketFlags.None,
					new AsyncCallback(onDataReceived), null);
			}
			catch(SocketException se)
			{
				Console.WriteLine(se.Message);
				disconnect();
			}
			
		}
		
		private void disconnect()
		{

			Status = Client.ConnectionState.Disconnected;
			socket = null;
			Disconnected(getHash(), null);
			
		}
		
		private void onDataReceived(IAsyncResult asyn) 
		{
			
			string messageReceived = null;
			
			try {

				if (Status == Client.ConnectionState.Waiting) {
					
					int iRx = socket.EndReceive(asyn);
					if (iRx == 0) { disconnect(); return; }
					
					Established(getHash(), null);
					Status = Client.ConnectionState.Established;

					char[] chars = new char[iRx + 1];
					System.Text.Decoder d = System.Text.Encoding.Default.GetDecoder();
					d.GetChars(dataBuffer, 0, iRx, chars, 0);
					messageReceived = new System.String(chars);

					authenticateHandshake(messageReceived);
					
				} else if (Status == Client.ConnectionState.Handshaking) {
					
					Status = Client.ConnectionState.Authenticated;
					Authenticated(getHash(), null);
					
				} else if (Status == Client.ConnectionState.Authenticated) {
					
					// Web Socket protocol: messages are sent with 0x00 and 0xFF as padding bytes
	                UTF8Encoding decoder = new UTF8Encoding();
	                int startIndex = 0;
	                int endIndex = 0;
	
	                // Search for the start byte
	                while (dataBuffer[startIndex] == FirstByte[0]) startIndex++;
	                // Search for the end byte
	                endIndex = startIndex + 1;
	                while (dataBuffer[endIndex] != LastByte[0]) endIndex++;
	
	                // Get the message
	                messageReceived = decoder.GetString(dataBuffer, startIndex, endIndex - startIndex);
					
					processRequest(messageReceived);					
				}
				
				Array.Clear(dataBuffer, 0, dataBuffer.Length);				
				waitForData();
				
			} catch {
				
				disconnect();	
			}
			
		}
		
		private static string ExtractNumbers( string expr )
		{
			return string.Join( null,System.Text.RegularExpressions.Regex.Split( expr, "[^\\d]" ) );
		}

		private void criteriaFailed(String msg)
		{
		
			Console.WriteLine(msg);
			disconnect();
			
		}
	
		private void authenticateHandshake(String msg)
		{
		
			Status = Client.ConnectionState.Handshaking;

			remoteHandshake = msg;
			ConnectionOrigin = remoteHandshake.Substring(remoteHandshake.IndexOf("Origin:")+8);
			ConnectionOrigin = ConnectionOrigin.Substring(0, ConnectionOrigin.IndexOf(Environment.NewLine));
			
			string key1 = remoteHandshake.Substring(remoteHandshake.IndexOf("Sec-WebSocket-Key1:")+20);
			key1 = key1.Substring(0, key1.IndexOf(Environment.NewLine));
			
			string key2 = remoteHandshake.Substring(remoteHandshake.IndexOf("Sec-WebSocket-Key2:")+20);
			key2 = key2.Substring(0, key2.IndexOf(Environment.NewLine));
			
			UInt32 nums1 = UInt32.Parse(ExtractNumbers(key1));
			UInt32 nums2 = UInt32.Parse(ExtractNumbers(key2));
			
			UInt32 spacesin1 = (UInt32)key1.Split(' ').Length - 1;
			UInt32 spacesin2 = (UInt32)key2.Split(' ').Length - 1;
			
			if ((spacesin1 < 1) || (spacesin1 > 12)) {
				criteriaFailed("Too little or too many spaces in keys to proceed.");
				return;
			}
			
			if ((nums1 % spacesin1 > 0) || (nums2 % spacesin2 > 0)) {
				criteriaFailed("Division of keys leaves remainder.");
				return;
			}
			
			UInt32 division1 = (UInt32)(nums1 / spacesin1);
			UInt32 division2 = (UInt32)(nums2 / spacesin2);
			
			string[] bodyText = remoteHandshake.Split(new char[] { '\r','\n' }, StringSplitOptions.RemoveEmptyEntries);
			string digest = bodyText[bodyText.Length-1];
			digest = digest.Substring(0, digest.Length-1);
			byte[] body = Encoding.Default.GetBytes(digest);
			
			if (body.Length != 8) {
				criteriaFailed("Key3 is not 8 bytes, failed. --> " + body.Length);
				return;
			}
			
			byte[] beInt1 = BitConverter.GetBytes(division1);
			byte[] beInt2 = BitConverter.GetBytes(division2);
			
			// Big-Endian Mode
			Array.Reverse(beInt1);
			Array.Reverse(beInt2);
			
			if ((beInt1.Length != 4) || (beInt2.Length != 4)) {
				criteriaFailed("Keys are not 4 bytes");
				return;
			}
			
			byte[] rv = new byte[ beInt1.Length + beInt2.Length + body.Length ];
		    System.Buffer.BlockCopy( beInt1, 0, rv, 0, beInt1.Length );
		    System.Buffer.BlockCopy( beInt2, 0, rv, beInt1.Length, beInt2.Length );
		    System.Buffer.BlockCopy( body, 0, rv, beInt1.Length + beInt2.Length, body.Length );
			
			if (rv.Length != 16) {
				criteriaFailed("Digest didn't end up being 16 bytes. Cannot proceed.");
				return;
			}
			
			MD5 m = new MD5CryptoServiceProvider();
			byte[] encodedResponse = m.ComputeHash(rv);
			
			byte[] standardHeader = Encoding.Default.GetBytes(getServerHandshake());
			byte[] compiledHeader = new byte [ standardHeader.Length + encodedResponse.Length ];
			System.Buffer.BlockCopy( standardHeader, 0, compiledHeader, 0, standardHeader.Length );
		    System.Buffer.BlockCopy( encodedResponse, 0, compiledHeader, standardHeader.Length, encodedResponse.Length );
			
			//Console.WriteLine("From Server:");
			Console.WriteLine(Encoding.Default.GetString(compiledHeader));
			
			socket.Send(compiledHeader);
			
		}
		
		public string getServerHandshake() 
        {
            string hs;
            hs = "HTTP/1.1 101 Web Socket Protocol Handshake" + Environment.NewLine;
            hs += "Upgrade: WebSocket" + Environment.NewLine;
            hs += "Connection: Upgrade" + Environment.NewLine;
            hs += "Sec-WebSocket-Origin: " + ConnectionOrigin + Environment.NewLine;
            hs += "Sec-WebSocket-Location: " + ServerLocation + Environment.NewLine;
            hs += Environment.NewLine;
            return hs;
        }
		
		private void processRequest(String msg)
		{
		
			Console.WriteLine(msg);
			
		}
		
		public void sendMessage(String msg)
		{
			
			if (Status == Client.ConnectionState.Authenticated) {
			
				byte[] bMsg = Encoding.UTF8.GetBytes(msg);
				byte[] wrappedOutput = new byte[ bMsg.Length + 2 ];
				
				System.Buffer.BlockCopy( FirstByte, 0, wrappedOutput, 0, 1 );
		    	System.Buffer.BlockCopy( bMsg, 0, wrappedOutput, 1, bMsg.Length );
				System.Buffer.BlockCopy( LastByte, 0, wrappedOutput, 1 + bMsg.Length, 1 );
				
				socket.Send(wrappedOutput);
				
			}
			
		}
		
	}
}

