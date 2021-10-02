import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.io.IOException;
import java.net.SocketTimeoutException;

public class Resolver {

	/**
	 * Converts our Java string (e.g. www.sandiego.edu) to the DNS-style
	 * string (e.g. (3)www(8)sandiego(3)edu(0).
	 *
	 * @param s The string you want to convert.
	 * @return Buffer containing the converted string.
	 */
	public static ByteBuffer stringToNetwork(String s) {
		ByteBuffer bb = ByteBuffer.allocate(s.length()+2);
		bb.order(ByteOrder.BIG_ENDIAN);

		String[] parts = s.split("\\.");
		for (String p : parts) {
			bb.put((byte)p.length());
			bb.put(p.getBytes());
		}

		bb.put((byte)0);

		return bb;
	}

	/**
	 * Converts a DNS-style string (e.g. (3)www(8)sandiego(3)edu(0) to the normal
	 * Java (e.g. www.sandiego.edu).
	 * This supports DNS-style name compression (see RFC 1035, Section 4.1.4).
	 *
	 * @param message The entire DNS message, in ByteBuffer format.
	 * @param start The location in the message buffer where the network
	 * 				string starts.
	 * @param sb StringBuilder to construct the string as we are reading the
	 * 				message.
	 * @return Location in message immediately after the string.
	 */
	private static int getStringFromDNS(ByteBuffer message, int start, StringBuilder sb) {
		int position = start;

		byte currByte = message.get(position);
		position += 1;

		while (currByte != 0) {
			byte length = currByte;

			// If length starts with "11" then this is a compressed name
			if ((length >> 6 & 3) == 3) {
				int lowerBits = message.get(position) & 0xFF;  // 8 least sig bits of offset
				int upperBits = (length & 0x3F) << 8; // 8 most sig bits of offset
				int offset = upperBits | lowerBits;

				getStringFromDNS(message, offset, sb);
				return position + 1;
			}

			for (int i = 0; i < length; i++) {
				byte c = message.get(position);
				sb.append((char)c);
				position += 1;
			}
			sb.append('.');

			currByte = message.get(position);
			position += 1;
		}

		sb.deleteCharAt(sb.length()-1);

		return position;
	}

	/**
	 * Constructs a DNS query for hostname's Type A record.
	 *
	 * @param hostname The host we are trying to resolve
	 * @return A ByteBuffer with the query
	 */
	public static ByteBuffer constructQuery(String hostname) {
		ByteBuffer bb = ByteBuffer.allocate(1024);

		// Network order is BIG_ENDIAN (opposite of what x86 uses)
		bb.order(ByteOrder.BIG_ENDIAN);

		bb.putShort((short)5); // id set to 5... should be random!
		bb.putShort((short)0); // flags (set to make an iterative request)

		// 1 question, no answers, no auth, or other records
		bb.putShort((short)1); // num questions
		bb.putShort((short)0); // num answers
		bb.putShort((short)0); // num auth
		bb.putShort((short)0); // num other

		// Create and add the host name
		ByteBuffer nameString = Resolver.stringToNetwork(hostname);
		bb.put(nameString.array(), 0, nameString.position());
		bb.putShort((short)1); // query type == 1 (i.e. Type A)
		bb.putShort((short)1); // class: INET

		return bb;
	}

    /**
     * Returns a string with the IP address (for an A record) or name of mail
     * server associated with the given hostname.
     *
     * @param hostname The name of the host to resolve.
     * @param isMX True if requesting the MX record result, False if
     *    requesting the A record.
     *
     * @return A string representation of an IP address (e.g. "192.168.0.1") or
     *    mail server (e.g. "mail.google.com"). If the request could not be
     *    resolved, null will be returned.
     */
    public static String resolve(String hostname, boolean isMX) {
        DatagramSocket sock;
        try {
            sock = new DatagramSocket();
            sock.setSoTimeout(5000); // set timeout to 5000ms (i.e. 5 seconds)
        } catch (SocketException e) {
            return null;
        }

		// construct a query and set that request
		ByteBuffer bb = constructQuery(hostname);

		String serverIP = "172.16.7.15"; // This is USD's local DNS server.
										 // You should NOT use it in your final
										 // program.


        InetAddress serverAddress;
        try {
            // Note: Using InetAddress.getByName in this project is only allowed
            // if the input is an IP address (i.e. don't give it "www.foo.com")
            serverAddress = InetAddress.getByName(serverIP);
        } catch (UnknownHostException e) {
            System.out.println("UnknownHostException");
            return null;
        }

		DatagramPacket request = new DatagramPacket(bb.array(), 
													bb.position(),
													serverAddress,
													53);
        try {
		    sock.send(request);
        } catch (IOException e) {
            System.out.println(e);
            System.exit(1);
        }

		ByteBuffer response_bb = ByteBuffer.allocate(1024);

		DatagramPacket response = new DatagramPacket(response_bb.array(),
														response_bb.capacity());

        // Receive the response, timing out if it takes more than 5 seconds.
		try {
			sock.receive(response);
		} catch (SocketTimeoutException ste) {
			System.out.println("Timed out!");
		} catch (Exception e) {
			System.out.println("Error receiving: " + e);
		}

		// TODO: Now you'll need to interpret the response by reading the
		// response_bb and interpretting the values you find there.

        return null;
    }

	public static void main(String[] args) throws Exception {
        String answer = resolve("www.sandiego.edu", false);

        if (answer != null) {
            System.out.println("Answer: " + answer);
        }
        else {
            System.out.println("Could not resolve request.");
        }
	}
}
