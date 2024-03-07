package dam.psp;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyStore;
import java.security.KeyStoreException;
public class Servidor {

	static KeyStore ks;


	public static void main(String[] args) {
		 try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e) {

		}
		try (ServerSocket ss = new ServerSocket(9000)) {
			while (true) {
				System.out.println("Esperando por el puerto 9000");
				Socket s = ss.accept();
				s.setSoTimeout(5000);
				System.out.println("Cliente Conectado: " + s.getInetAddress().toString());
				Usuario u = new Usuario(s);
				u.start();
			}
		} catch (IOException e1) {

		}

	}



}

























/*

*/