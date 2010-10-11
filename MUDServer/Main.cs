using System;
using System.Net;
using System.Net.Sockets;
using System.Collections;

namespace MUDServer
{
	class MainClass
	{
		
		private Hashtable clients = new Hashtable();
		private Socket mainSocket;
		
		public static void Main (string[] args)
		{
			Console.WriteLine ("Initializing Server.");
			
			MainClass server = new MainClass();
			server.startServer();
			server.Dispose();
			
		}
		
		~MainClass() {
			
			Dispose();
			
		}
		
		public void Dispose()
		{
			
			mainSocket = null;
			clients = null;
  			System.GC.SuppressFinalize(this);
			
		}
		
		public void startServer() 
		{
		
			mainSocket = new Socket(AddressFamily.InterNetwork, 
				                          SocketType.Stream, 
				                          ProtocolType.IP);
						
			mainSocket.Bind(new IPEndPoint(IPAddress.Any, 1167));
			mainSocket.Listen(100);
			
			mainSocket.BeginAccept(new AsyncCallback (OnClientConnect), null);
			Console.WriteLine("Waiting for connections on port 1167");
			
			string ConsoleInput;
			while (true)
            {
                ConsoleInput = Console.ReadLine();
				if (ConsoleInput != null) {
					if (ConsoleInput.ToLower() == "q") {
						break;	
					}
				}
				System.Threading.Thread.Sleep(1);
            }
			
			
		}
		
		public void OnClientConnect(IAsyncResult asyn)
		{
			
			try {
			
				Client newClient = new Client(mainSocket.EndAccept(asyn));
				newClient.Disconnected += HandleNewClientDisconnected;	// Listen for disconnects
				
				Console.WriteLine("Client connected (" + newClient.getHash() + ")");
				
				clients.Add(newClient.getHash(), newClient);
			
				// Listen for more connections
				mainSocket.BeginAccept(new AsyncCallback (OnClientConnect), null);
				
			}
			catch(ObjectDisposedException)
			{
				System.Diagnostics.Debugger.Log(0,"1","\n OnClientConnection: Socket has been closed\n");
			}
			catch(SocketException se)
			{
				Console.WriteLine ( se.Message );
			}
			
			
			
		}

		void HandleNewClientDisconnected (int hash, EventArgs e)
		{
			
			clients.Remove(hash);
			Console.WriteLine("Disconnected: " + hash);
			
		}
		
	}
}

