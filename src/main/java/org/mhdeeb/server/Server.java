package org.mhdeeb.server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Optional;
import java.util.TimeZone;
import java.util.Map.Entry;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Server {
	private static final int LISTENING_PORT = 80;
	private static final int LISTENING_PORT_S = 443;

	private static final int TIMEOUT = 15000;

	private static int cacheTime = 600;

	private static final int DEFAULT_ERROR_CODE = 501;

	private static final int MAX_BUFFER_SIZE = 16_777_216;

	private static final String[] ALLOWED_HTTP = { "HTTP/1.1", "HTTP/1.0" };

	private static final String DEFAULT_HTTP_SPEC = ALLOWED_HTTP[0];

	private static Path resourceDirectory = Paths.get("./");

	private static final String CRLF = "\r\n";

	private static final String TRUST_STORE_PWD = Extern.getPassword();
	private static final String KEY_STORE_PWD = Extern.getPassword();

	private static final ArrayList<String> BLACK_LIST = (ArrayList<String>) Extern.getBlackList();

	private static final ObjectMapper mapper = new ObjectMapper();

	private static final Logger logger = LogManager.getLogger(Server.class);

	private static class ResponseHeader {
		private final HashMap<String, String> header = new HashMap<>();

		private String spec;
		private int statusCode;

		private static String getStatusString(int statusCode) {
			return switch (statusCode) {
				case 200 -> "OK";
				case 204 -> "No Content";
				case 206 -> "Partial Content";
				case 304 -> "Not Modified";
				case 400 -> "Bad Request";
				case 403 -> "Forbidden";
				case 404 -> "Not Found";
				case 500 -> "Internal Server Error";
				case 501 -> "Not Implemented";
				default -> "Unknown";
			};
		}

		public void setSpec(String spec) {
			this.spec = spec;
		}

		public void setStatusCode(int statusCode) {
			this.statusCode = statusCode;
		}

		public void add(String key, String value) {
			header.put(key, value);
		}

		public void add(String key, int value) {
			header.put(key, Integer.toString(value));
		}

		public void add(String key, long value) {
			header.put(key, Long.toString(value));
		}

		@Override
		public String toString() {
			StringBuilder response = new StringBuilder();

			response.append(spec).append(" ").append(statusCode).append(" ").append(getStatusString(statusCode))
					.append(CRLF);

			for (Entry<String, String> entry : header.entrySet()) {
				response.append(entry.getKey()).append(": ").append(entry.getValue()).append(CRLF);
			}

			response.append(CRLF);

			return response.toString();
		}
	}

	private static Path getResourceDirectory() {
		return resourceDirectory;
	}

	private static Path getWWWDirectory() {
		return Paths.get(getResourceDirectory().toString(), "WWW");
	}

	private static Path getErrorDirectory() {
		return Paths.get(getWWWDirectory().toString(), "error");
	}

	private static Path getRootDirectory() {
		return Paths.get(getWWWDirectory().toString(), "content");
	}

	private static Path getImageDirectory() {
		return Paths.get(getRootDirectory().toString(), "image");
	}

	private static Path getImage(String name) {
		return Paths.get(getImageDirectory().toString(), name);
	}

	private static Path getUploadDirectory() {
		return Paths.get(getRootDirectory().toString(), "upload");
	}

	private static Path getTrustStorePath() {
		return Paths.get(getWWWDirectory().toString(), "cert.p12");
	}

	private static Path getKeyStorePath() {
		return Paths.get(getWWWDirectory().toString(), "cert.p12");
	}

	private static String getMimeType(String fileName) {
		int pos = fileName.lastIndexOf('.');

		if (pos < 0)
			return "x-application/x-unknown";

		String ext = fileName.substring(pos + 1).toLowerCase();

		return switch (ext) {
			case "txt" -> "text/plain";
			case "html" -> "text/html";
			case "htm" -> "text/html";
			case "css" -> "text/css";
			case "js" -> "text/javascript";
			case "java" -> "text/x-java";
			case "jpeg" -> "image/jpeg";
			case "jpg" -> "image/jpeg";
			case "png" -> "image/png";
			case "gif" -> "image/gif";
			case "ico" -> "image/x-icon";
			case "svg" -> "image/svg+xml";
			case "ttf" -> "font/ttf";
			case "webp" -> "image/webp";
			case "mp3" -> "audio/mpeg";
			case "mp4" -> "video/mp4";
			case "wav" -> "audio/wav";
			case "avi" -> "video/x-msvideo";
			case "mpeg" -> "video/mpeg";
			case "ogg" -> "application/ogg";
			case "class" -> "application/java-vm";
			case "jar" -> "application/java-archive";
			case "zip" -> "application/zip";
			case "xml" -> "application/xml";
			case "xhtml" -> "application/xhtml+xml";
			default -> "x-application/x-unknown";
		};
	}

	private static boolean isMimeText(String mimeType) {
		return switch (mimeType) {
			case "text/plain", "text/html", "text/css", "text/javascript", "text/x-java", "image/svg+xml",
					"application/xml", "application/xhtml+xml" ->
				true;
			default -> false;
		};
	}

	private static String getExpireDate(int field, int amount) {
		Calendar calendar = Calendar.getInstance();

		calendar.add(field, amount);

		SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);

		dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));

		return dateFormat.format(calendar.getTime());
	}

	private static String getETag(File file) {
		return Long.toHexString(file.lastModified()) + "-" + Long.toHexString(file.length()) + "-"
				+ Long.toHexString(file.hashCode());
	}

	private static void send(int statusCode, OutputStream socketOut, File file, String etag)
			throws IOException {
		PrintWriter out = new PrintWriter(socketOut);

		ResponseHeader responseHeader = new ResponseHeader();

		responseHeader.setSpec(DEFAULT_HTTP_SPEC);
		responseHeader.setStatusCode(statusCode);

		responseHeader.add("Connection", "close");
		responseHeader.add("Expires", getExpireDate(Calendar.SECOND, cacheTime));
		responseHeader.add("Cache-Control", "max-age=" + cacheTime);
		if (etag != null)
			responseHeader.add("ETag", etag);
		else
			responseHeader.add("ETag", getETag(file));
		String mimeType = getMimeType(file.getName());
		responseHeader.add("Content-Type", mimeType + (isMimeText(mimeType) ? "; charset=utf-8" : ""));
		responseHeader.add("Accept-Ranges", "bytes");
		responseHeader.add("Content-Length", file.length());

		out.write(responseHeader.toString());

		out.flush();

		sendFile(file, socketOut);
	}

	private static void sendChunked(OutputStream socketOut, File file, long start, long end)
			throws IOException {
		PrintWriter out = new PrintWriter(socketOut);

		long fileSize = file.length();

		if (start > fileSize - 1 || start < 0 || start > end || end < 0)
			throw new IOException("Invalid range.");

		long len = end - start + 1;

		if (len > MAX_BUFFER_SIZE) {
			len = MAX_BUFFER_SIZE;
			end = start + len - 1;
		}

		if (end >= fileSize - 1)
			end = fileSize - 1;

		ResponseHeader responseHeader = new ResponseHeader();

		responseHeader.setSpec(DEFAULT_HTTP_SPEC);
		responseHeader.setStatusCode(206);

		responseHeader.add("Connection", "close");
		responseHeader.add("Expires", getExpireDate(Calendar.SECOND, cacheTime));
		responseHeader.add("Cache-Control", "max-age=" + cacheTime);
		responseHeader.add("ETag", getETag(file));
		responseHeader.add("Content-Type", getMimeType(file.getName()));
		responseHeader.add("Content-Length", len);
		responseHeader.add("Content-Range", String.format("bytes %d-%d/%d", start, end, fileSize));

		out.write(responseHeader.toString());

		out.flush();

		sendFileChunked(file, socketOut, start, len);
	}

	private static void sendFileChunked(File file, OutputStream socketOut, long offset, long len) throws IOException {
		BufferedOutputStream out = new BufferedOutputStream(socketOut);

		try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(file), MAX_BUFFER_SIZE)) {
			long skipped = in.skip(offset);

			if (skipped != offset)
				throw new IOException("Failed to skip to offset.");

			byte[] buffer = new byte[MAX_BUFFER_SIZE];

			int bytesRead;

			while (len > 0 && (bytesRead = in.read(buffer, 0, (int) Math.min(buffer.length, len))) != -1) {
				out.write(buffer, 0, bytesRead);
				len -= bytesRead;
			}

			out.flush();
		}
	}

	private static void sendFile(File file, OutputStream socketOut) throws IOException {
		BufferedOutputStream out = new BufferedOutputStream(socketOut);

		try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(file), MAX_BUFFER_SIZE)) {

			byte[] buffer = new byte[1024];

			int bytesRead;

			while ((bytesRead = in.read(buffer)) != -1)
				out.write(buffer, 0, bytesRead);

			out.flush();
		}
	}

	static void sendNoContentResponse(OutputStream socketOut) throws IOException {
		socketOut.write(String.format("%s 204 No Content%s%s", DEFAULT_HTTP_SPEC, CRLF, CRLF).getBytes());
	}

	static void sendNotModifiedResponse(OutputStream socketOut, String etag) throws IOException {
		ResponseHeader responseHeader = new ResponseHeader();

		responseHeader.setSpec(DEFAULT_HTTP_SPEC);
		responseHeader.setStatusCode(304);

		responseHeader.add("Expires", getExpireDate(Calendar.SECOND, cacheTime));
		responseHeader.add("Cache-Control", "max-age=" + cacheTime);
		responseHeader.add("ETag", etag);

		socketOut.write(responseHeader.toString().getBytes());
	}

	static void sendErrorResponse(int errorCode, OutputStream socketOut) throws IOException {
		File file = new File(Paths.get(getErrorDirectory().toString(), errorCode + ".html").toString());

		if (!file.exists()) {
			file = new File(Paths.get(getErrorDirectory().toString(), DEFAULT_ERROR_CODE + ".html").toString());
		}

		send(errorCode, socketOut, file, null);
	}

	private static void sendBanResponse(Socket connection) throws IOException {
		File file = new File(Paths.get(getErrorDirectory().toString(), "Ban.html").toString());

		if (!file.exists()) {
			file = new File(Paths.get(getErrorDirectory().toString(), DEFAULT_ERROR_CODE + ".html").toString());
		}

		send(200, connection.getOutputStream(), file, null);
	}

	private static void sendDirectoryListing(OutputStream out, File directory) throws IOException {
		PrintWriter writer = new PrintWriter(out);

		ResponseHeader responseHeader = new ResponseHeader();

		responseHeader.setSpec(DEFAULT_HTTP_SPEC);
		responseHeader.setStatusCode(200);
		responseHeader.add("Connection", "close");
		responseHeader.add("content-type", "text/html; charset=utf-8");

		StringBuilder response = new StringBuilder();

		String relativeDirectoryImageString = "/" + getRootDirectory().relativize(getImage("folder.svg")).toString()
				.replace("\\", "/");
		String relativeFileImageString = "/"
				+ getRootDirectory().relativize(getImage("file.svg")).toString().replace("\\",
						"/");
		String relativeParentImageString = "/" + getRootDirectory().relativize(getImage("undo.svg")).toString()
				.replace("\\", "/");

		String relativeParentImageHTML = "<td valign=\"top\">\n<img src=\"" + relativeParentImageString
				+ "\" alt=\"Parent Directory\" width=\"20\" height=\"22\">\n</td>\n";

		String relativeFileImageHTML = "<td valign=\"top\">\n<img src=\"" + relativeFileImageString
				+ "\" alt=\"Parent Directory\" width=\"20\" height=\"22\">\n</td>\n";

		String relativeDirectoryImageHTML = "<td valign=\"top\">\n<img src=\"" + relativeDirectoryImageString
				+ "\" alt=\"Parent Directory\" width=\"20\" height=\"22\">\n</td>\n";

		Path relativeDirectoryPath = getRootDirectory().relativize(directory.toPath());
		String relativeDirectoryString = relativeDirectoryPath.toString().replace("\\", "/");

		response.append(
				"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\" />\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n<title>Index of /");
		response.append(relativeDirectoryString);
		response.append("</title>\n</head>\n<body>\n<h1>Index of /");
		response.append(relativeDirectoryString);
		response.append("</h1>\n<table>\n<tbody>\n");

		if (relativeDirectoryString.length() > 0) {
			response.append("<tr>\n");
			response.append("<tr>\n");

			response.append("<tr>\n");

			response.append(relativeParentImageHTML);
			response.append("<td>\n<a href=\"/");
			Path relativeDirectoryParentPath = relativeDirectoryPath.getParent();
			response.append((relativeDirectoryParentPath == null ? "" : relativeDirectoryParentPath).toString());
			response.append("\">../</a>\n</td>\n</tr>\n");
		}

		File[] directories = directory.listFiles(File::isDirectory);
		if (directories != null) {
			for (File d : directories) {
				Path relative = getRootDirectory().relativize(d.toPath());
				response.append("<tr>\n");
				response.append(relativeDirectoryImageHTML);
				response.append("<td>\n<a href=\"/");
				response.append(relative.toString());
				response.append("\">");
				response.append(relative.getFileName().toString());
				response.append("/</a>\n</td>\n</tr>\n");
			}
		}

		File[] files = directory.listFiles(File::isFile);
		if (files != null) {
			for (File file : files) {
				Path relative = getRootDirectory().relativize(file.toPath());
				response.append("<tr>\n");

				response.append(relativeFileImageHTML);

				response.append("<td>\n<a href=\"/");
				response.append(relative.toString());
				response.append("\">");
				response.append(relative.getFileName().toString());
				response.append("</a>\n</td>\n");

				response.append("</tr>\n");
			}
		}

		response.append("</tbody>\n</table>\n</body>\n</html>\n");

		responseHeader.add("Content-Length", response.length());

		writer.write(responseHeader.toString());

		writer.flush();

		writer.write(response.toString());

		writer.flush();
	}

	private static void parseQuery(LinkedHashMap<String, String> map, String query) {
		String[] tokens = query.split("&");

		for (String token : tokens) {
			String[] pair = token.split("=");

			if (pair.length == 1) {
				map.put(pair[0], "");
			} else {
				map.put(pair[0], pair[1]);
			}
		}
	}

	static String read(BufferedInputStream in, String delimiter) throws IOException {
		StringBuilder request = new StringBuilder();

		char[] delimiterTestBuffer = new char[delimiter.length()];
		int c;

		while ((c = in.read()) != -1) {
			if (c != delimiter.charAt(0)) {
				request.append((char) c);
			} else {
				delimiterTestBuffer[0] = (char) c;

				for (int i = 1; i < delimiter.length(); i++) {
					c = in.read();
					if (c == -1) {
						request.append(delimiterTestBuffer, 0, i);
						return request.toString();
					} else {
						delimiterTestBuffer[i] = (char) c;
					}
				}

				if (new String(delimiterTestBuffer).equals(delimiter)) {
					return request.toString();
				} else {
					request.append(delimiterTestBuffer, 0, delimiter.length());
				}
			}
		}
		return request.toString();
	}

	static String readLine(BufferedInputStream in) throws IOException {
		return read(in, CRLF);
	}

	private static SSLServerSocketFactory getSocketFactory() throws IOException {
		try (InputStream tstore = new FileInputStream(getTrustStorePath().toString());
				InputStream kstore = new FileInputStream(getKeyStorePath().toString());) {
			KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
			trustStore.load(tstore, TRUST_STORE_PWD.toCharArray());
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(trustStore);

			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(kstore, KEY_STORE_PWD.toCharArray());
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(keyStore, KEY_STORE_PWD.toCharArray());
			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
			return ctx.getServerSocketFactory();
		} catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException
				| KeyManagementException | IOException e) {
			logger.fatal("Failed to create listening socket.");
			throw new IOException(e);
		}
	}

	private static Thread getThread(ServerSocket serverSocket) {
		return new Thread(() -> {
			while (true) {
				try {
					Socket connection = serverSocket.accept();
					connection.setSoTimeout(TIMEOUT);

					new Thread(() -> handleConnection(connection)).start();
				} catch (IOException e) {
					logger.debug("Server socket shut down unexpectedly!");
					logger.error(e.getStackTrace());
				}
			}

		});
	}

	private static boolean isBlocked(String address) {
		return BLACK_LIST.stream().anyMatch(address::equals);
	}

	public static void main(String[] args) {
		Options options = new Options();

		Option cacheOption = new Option("c", "cache", true, "cache time in seconds");
		cacheOption.setRequired(false);
		cacheOption.setType(Integer.class);
		options.addOption(cacheOption);

		Option resourceOption = new Option("r", "resource", true, "resource directory");
		resourceOption.setRequired(false);
		options.addOption(resourceOption);

		CommandLineParser parser = new DefaultParser();
		HelpFormatter formatter = new HelpFormatter();
		CommandLine cmd = null;

		try {
			cmd = parser.parse(options, args);
		} catch (ParseException e) {
			logger.error(e.getStackTrace());
			formatter.printHelp("java-server", options);
			System.exit(1);
		}

		String cache = cmd.getOptionValue("cache");
		if (cache != null) {
			try {
				cacheTime = Integer.parseInt(cache);
			} catch (NumberFormatException e) {
				logger.fatal("Invalid cache time.");
				System.exit(1);
			}
		}

		String resource = cmd.getOptionValue("resource");
		if (resource != null) {
			try {
				resourceDirectory = Paths.get(resource);
			} catch (InvalidPathException e) {
				logger.fatal("Invalid resource directory.");
				System.exit(1);
			}
		}

		try (
				ServerSocket serverSocket = new ServerSocket(LISTENING_PORT);
				SSLServerSocket serverSocketS = (SSLServerSocket) getSocketFactory()
						.createServerSocket(LISTENING_PORT_S);) {

			logger.info("Listening on port " + LISTENING_PORT_S);
			Thread threadS = getThread(serverSocketS);

			logger.info("Listening on port " + LISTENING_PORT);
			Thread thread = getThread(serverSocket);

			threadS.start();
			thread.start();

			threadS.join();
			thread.join();
		} catch (Exception e) {
			logger.debug("Failed to create listening socket.");
			logger.fatal(e.getStackTrace());
			Thread.currentThread().interrupt();
		}
	}

	private static void handleConnection(Socket connection) {
		InetAddress address = connection.getInetAddress();

		if (address == null)
			return;

		String ip = address.getHostAddress();

		try {
			if (isBlocked(ip)) {
				logger.info("{} is banned.", ip);
				connection.close();
				return;
			}

			String ipLookUp = Util.getIPLookUp(ip, mapper);
			logger.info("{} connected from {}", ip, ipLookUp);

			BufferedInputStream in = new BufferedInputStream(connection.getInputStream());
			OutputStream out = connection.getOutputStream();

			String requestType;
			String requestPath;
			String requestProtocol;
			LinkedHashMap<String, String> query = new LinkedHashMap<>();

			String line = readLine(in);

			String[] tokens = line.split(" ");

			if (tokens.length != 3) {
				sendErrorResponse(400, out);
				String hex = Util.toHex(line);
				logger.warn("Bad request: {} :: {}", ip, hex);
				return;
			}

			String[] requestPathTokens = tokens[1].split("\\?");

			requestType = tokens[0];
			requestPath = requestPathTokens[0];
			requestProtocol = tokens[2];

			if (requestPathTokens.length > 1) {
				parseQuery(query, requestPathTokens[1]);

				for (Entry<String, String> entry : query.entrySet()) {
					logger.info("{}:: {} = {}", ip, entry.getKey(), entry.getValue());
				}
			}

			logger.info("{}:: {} {} {}", ip, requestType, requestPath,
					requestProtocol);

			if (Arrays.stream(ALLOWED_HTTP).noneMatch(requestProtocol::equals)) {
				sendErrorResponse(400, out);
				connection.close();
				logger.warn("{} is not supported :: {}", requestProtocol, ip);
				return;
			}

			HashMap<String, String> header = new HashMap<>();

			while (!(line = readLine(in)).isEmpty()) {
				tokens = line.split(": ", 2);
				header.put(tokens[0], tokens[1]);
			}

			if (requestType.equals("GET")) {

				Path path = Paths.get(getRootDirectory().toString(), requestPath);

				if (!Files.exists(path)) {
					sendErrorResponse(404, out);
					return;
				}

				File file = new File(path.toString());

				try {
					if (file.isDirectory()) {
						Path indexFile = Paths.get(file.toString(), "index.html");
						if (Files.exists(indexFile)) {
							file = new File(indexFile.toString());
							send(200, out, file, null);
						} else {
							sendDirectoryListing(out, file);
						}
					} else if (header.containsKey("Range")) {
						String[] range = header.get("Range").split("=");

						if (!range[0].equals("bytes") || range.length < 2) {
							sendErrorResponse(400, out);
							return;
						}

						String[] ranges = range[1].split(", ");

						for (String r : ranges) {
							String[] startEnd = r.split("-");

							if (startEnd.length == 2) {
								long start;
								long end;

								try {
									start = Long.parseLong(startEnd[0]);
									end = Long.parseLong(startEnd[1]);
								} catch (NumberFormatException e) {
									sendErrorResponse(400, out);
									return;
								}

								sendChunked(out, file, start, end);
							} else if (startEnd.length == 1) {
								long limit;

								try {
									limit = Long.parseLong(startEnd[0]);
								} catch (NumberFormatException e) {
									sendErrorResponse(400, out);
									return;
								}

								if (r.charAt(0) == '-') {
									sendChunked(out, file, 0, limit);
								} else if (r.charAt(r.length() - 1) == '-') {
									sendChunked(out, file, limit, file.length() - 1);
								} else {
									sendErrorResponse(400, out);
									return;
								}

							} else {
								sendErrorResponse(400, out);
								return;
							}
						}
					} else {
						String etag = getETag(file);
						if (header.containsKey("If-None-Match")
								&& header.get("If-None-Match").equals(etag)) {
							sendNotModifiedResponse(out, etag);
						} else {
							send(200, out, file, etag);
						}
					}
				} catch (IOException e) {
					sendErrorResponse(403, out);
				}

			} else if (requestType.equals("POST")) {

				String[] contentType = header.get("Content-Type").split("; ");

				if (contentType[0].equals("text/plain")) {
					if (!(line = readLine(in)).isEmpty()) {
						parseQuery(query, line);

						for (Entry<String, String> entry : query.entrySet()) {
							logger.info("{}:: {} = {}", ip, entry.getKey(), entry.getValue());
						}
					}
				} else if (contentType[0].equals("multipart/form-data")) {
					String boundary = CRLF + readLine(in);

					byte[] boundaryTestBuffer = new byte[boundary.length()];

					String contentDisposition;

					loop: while (!(contentDisposition = readLine(in)).isEmpty()) {

						@SuppressWarnings("unused")
						String fileContentType = readLine(in);

						String fileName = contentDisposition.split("filename=\"", 2)[1].split("\"", 2)[0];

						if (fileName.isEmpty()) {
							break;
						}

						try {
							FileOutputStream fileOutputStream = new FileOutputStream(
									Paths.get(getUploadDirectory().toString(), fileName).toString());

							readLine(in);

							int c;
							while ((c = in.read()) != -1) {

								if (c != boundary.charAt(0)) {
									fileOutputStream.write(c);
								} else {
									boundaryTestBuffer[0] = (byte) c;

									boolean boundaryFound = true;

									for (int i = 1; i < boundary.length(); i++) {
										if ((c = in.read()) == -1) {
											throw new IOException("Unexpected end of stream.");
										}

										boundaryTestBuffer[i] = (byte) c;

										if (boundaryTestBuffer[i] != boundary.charAt(i)) {
											fileOutputStream.write(boundaryTestBuffer, 0, i + 1);
											boundaryFound = false;
											break;
										}
									}

									if (boundaryFound) {
										if (in.read() != '\r') {
											in.read();
											in.read();

											fileOutputStream.close();
											break loop;
										}

										in.read();
										break;
									}
								}
							}

							fileOutputStream.close();
						} catch (IOException e) {
							try {
								sendErrorResponse(500, out);
							} catch (IOException ioException) {
								ioException.printStackTrace();
							}
						}
					}
				}

				sendNoContentResponse(out);
			} else {
				sendErrorResponse(501, out);
			}

			in.close();
			out.close();

		} catch (javax.net.ssl.SSLHandshakeException e) {
			logger.error("{} failed to establish SSL connection.", ip);
		} catch (java.net.SocketTimeoutException e) {
			try {
				sendNoContentResponse(connection.getOutputStream());
			} catch (IOException ioException) {
				logger.debug(ioException.getStackTrace());
			}
			logger.debug("Socket timeout occurred - killing connection");
		} catch (java.net.SocketException e) {
			logger.error("Socket exception occurred - killing connection");

			logger.error(e.getMessage());
		} catch (IOException e) {
			logger.error("I/O error occurred - killing connection");
		} finally {
			try {
				connection.close();
			} catch (Exception e) {
				e.printStackTrace();
			}

			logger.info("Connection closed:: {}", ip);
		}
	}

}
