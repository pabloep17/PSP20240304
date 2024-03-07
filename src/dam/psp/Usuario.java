package dam.psp;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Usuario extends Thread {
	
	Socket cliente;
	DataInputStream in;
	DataOutputStream out;
	
	public Usuario(Socket s) {
		this.cliente = s;
		try {
			in = new DataInputStream(s.getInputStream());
			out = new DataOutputStream(cliente.getOutputStream());
		} catch (IOException e) {
		}
	}

	@Override
	public void run() {
		try {
			String command = in.readUTF();
			switch (command) {
			case "hash": {
				obtenerHash();
				break;
			}
			case "cert": {
				guardarUnCertificado();
				break;
			}
			case "cifrar": {
				cifrar();
				break;
			}
			default:
				sendMessage("ERROR:'" + command + "' no se reconoce como una petición válida");
				cliente.close();
			}
		} catch (SocketTimeoutException e) {
			sendMessage("ERROR:Read timed out");
		} catch (EOFException e) {
			sendMessage("ERROR:Se esperaba una petición");
		} catch (IOException e) {
		}

	}

	private void obtenerHash() {
		try {
			MessageDigest md;
			String algoritmo = in.readUTF();
			md = MessageDigest.getInstance(algoritmo);
			byte[] bytes = in.readAllBytes();
			if (bytes.length > 0) {
				String cadena = Base64.getEncoder().encodeToString(md.digest(bytes));
				sendMessage("OK:" + cadena);
			} else {
				sendMessage("ERROR:Se esperaban datos");
				cliente.close();
			}
		} catch (SocketTimeoutException e) {
			sendMessage("ERROR:Read timed out");
			try {
				cliente.close();
			} catch (IOException e1) {;
			}
		} catch (EOFException e) {
			sendMessage("ERROR:Se esperaba un algoritmo");
			try {
				cliente.close();
			} catch (IOException e1) {
			}
		} catch (IOException | NoSuchAlgorithmException e) {
		}

	}

	private void cifrar() {
		String alias = "";
		try {
			alias = in.readUTF();
			Certificate cert = Servidor.ks.getCertificate(alias);
			if (cert == null)
				sendMessage("ERROR:'" + alias + "' no es un certificado");
			else {
				Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				c.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
				int n;
				byte[] bloque = new byte[256];
				int contador = 0;
				while ((n = in.read(bloque)) != -1) {
					contador += 1;
					byte[] cifrado = c.doFinal(bloque, 0, n);
					sendMessage("OK:" + Base64.getEncoder().encodeToString(cifrado));
				}
				if (contador == 0) {
					sendMessage("ERROR:Se esperaban datos");
					cliente.close();
				}
			}
		} catch (SocketTimeoutException e) {
			sendMessage("ERROR:Read timed out");
			try {
				cliente.close();
			} catch (IOException e1) {
			}
		} catch (NoSuchAlgorithmException e) {
		} catch (EOFException e) {
			sendMessage("ERROR:Se esperaba un alias");
			try {
				cliente.close();
			} catch (IOException e1) {
			}
		} catch (KeyStoreException e) {
		} catch (NoSuchPaddingException e) {
		} catch (InvalidKeyException e) {
			sendMessage("ERROR:'" + alias + "' no contiene una clave RSA");
			try {
				cliente.close();
			} catch (IOException e1) {
			}
		} catch (IllegalBlockSizeException e) {
		} catch (BadPaddingException e) {
		} catch (IOException e) {
		}

	}
	
	private void guardarUnCertificado() {
		try {
			String alias = in.readUTF();
			try {
				String base = in.readUTF();
				CertificateFactory f = CertificateFactory.getInstance("X.509");
				byte[] byteEncoded = Base64.getDecoder().decode(base);
				Certificate cert = f.generateCertificate(new ByteArrayInputStream(byteEncoded));
				Servidor.ks.setCertificateEntry(alias, cert);
				MessageDigest md;
				md = MessageDigest.getInstance("SHA-256");
				md.update(base.getBytes());
				String cadena = Base64.getEncoder().encodeToString(md.digest());
				sendMessage("OK: " + cadena);
			} catch (CertificateException e) {
				cliente.close();
			} catch (IllegalArgumentException e) {
				sendMessage("ERROR:Se esperaba Base64");
				cliente.close();
			} catch (EOFException e) {
				sendMessage("ERROR:Se esperaba un certificado");
				cliente.close();
			} catch (SocketTimeoutException e) {
				sendMessage("ERROR:Read timed out");
				cliente.close();
			}
		} catch (EOFException e) {
			sendMessage("ERROR:Se esperaba un alias");
			try {
				cliente.close();
			} catch (IOException e1) {
			}
		} catch (SocketTimeoutException e) {
			sendMessage("ERROR:Read timed out");
			try {
				cliente.close();
			} catch (IOException e1) {
			}
		} catch (IOException e) {
		} catch (KeyStoreException e) {;
		} catch (NoSuchAlgorithmException e) {
		}
	}
	
	private void sendMessage(String message) {
		try {
			out.writeUTF(message);
		} catch (SocketTimeoutException e) {
			try {
				out.writeUTF("ERROR:Read timed out");
				cliente.close();
			} catch (IOException error) {
				
			}
		} catch (IOException e) {
		}
	}
	
}


























