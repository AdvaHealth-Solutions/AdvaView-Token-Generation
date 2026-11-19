package com.advahealthsolutions.advapacs.demo;

/**
 * Turns command-line arguments into a {@link Config}.
 *
 * <p>This is only plumbing for the example. In your own integration these values would typically
 * come from your application: the signed-in user, the studies they are viewing, and the access key
 * stored in your secrets manager.
 */
public class ArgParser {

  public Config parse(String[] args) {
    Config config = new Config();

    for (int i = 0; i < args.length; i++) {
      String arg = args[i];

      if (!arg.startsWith("--")) {
        throw new IllegalArgumentException("Unexpected argument: " + arg);
      }

      String key = arg.substring(2);

      // Every option takes a value.
      if (i + 1 >= args.length || args[i + 1].startsWith("--")) {
        throw new IllegalArgumentException("Missing value for argument: " + arg);
      }
      String value = args[++i];

      switch (key) {
        case "suid" -> config.addSuid(value); // may be repeated
        case "patientId" -> config.setPatientId(value);
        case "accNum" -> config.addAccNum(value); // may be repeated
        case "username" -> config.setUsername(value);
        case "mode" -> config.setMode(JoseMode.fromString(value));
        case "accessKeySecret" -> config.setAccessKeySecret(value);
        case "accessKeyId" -> config.setAccessKeyId(value);
        case "expireAfter" -> config.setExpireAfter(Integer.parseInt(value));
        default -> throw new IllegalArgumentException("Unknown argument: " + arg);
      }
    }

    config.validate();
    return config;
  }
}
