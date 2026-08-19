import network.luibara.endlinkguard.EndlinkGuardExtension;

import java.lang.reflect.Method;

/**
 * Exercises the Geyser build's response validation against the same rules the Python builds apply.
 * Standalone rather than JUnit because this project deliberately builds the extension with plain
 * javac and no dependency resolution.
 */
public final class ValidateTest {
    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        EndlinkGuardExtension extension = new EndlinkGuardExtension();
        Method validate = EndlinkGuardExtension.class
                .getDeclaredMethod("validate", String.class, String.class);
        validate.setAccessible(true);

        String good = body("luibara2", "2535459084817261",
                "3babcf62-2d0e-3952-bb4c-b90f73cd1ebe", "203.0.113.42", 42123);

        check("accepts a well-formed identity", accepted(validate, extension, good, "luibara2"));
        check("matches the name case-insensitively",
                accepted(validate, extension, good, "LUIBARA2"));

        check("rejects a name that is not the one asked about",
                !accepted(validate, extension, good, "someone-else"));
        check("rejects a non-numeric XUID",
                !accepted(validate, extension, body("luibara2", "25354x9084817261",
                        "3babcf62-2d0e-3952-bb4c-b90f73cd1ebe", "203.0.113.42", 1), "luibara2"));
        check("rejects an empty XUID",
                !accepted(validate, extension, body("luibara2", "",
                        "3babcf62-2d0e-3952-bb4c-b90f73cd1ebe", "203.0.113.42", 1), "luibara2"));
        check("rejects a malformed UUID",
                !accepted(validate, extension, body("luibara2", "2535459084817261",
                        "not-a-uuid", "203.0.113.42", 1), "luibara2"));
        check("rejects a real_ip that is not an address",
                !accepted(validate, extension, body("luibara2", "2535459084817261",
                        "3babcf62-2d0e-3952-bb4c-b90f73cd1ebe", "999.999.999.999", 1), "luibara2"));
        check("rejects a hostname in real_ip rather than resolving it",
                !accepted(validate, extension, body("luibara2", "2535459084817261",
                        "3babcf62-2d0e-3952-bb4c-b90f73cd1ebe", "localhost", 1), "luibara2"));
        check("rejects a port outside the legal range",
                !accepted(validate, extension, body("luibara2", "2535459084817261",
                        "3babcf62-2d0e-3952-bb4c-b90f73cd1ebe", "203.0.113.42", 70000), "luibara2"));

        // An absent endpoint is legitimate: the proxy omits it when it has nothing to forward.
        check("accepts an empty real_ip",
                accepted(validate, extension, body("luibara2", "2535459084817261",
                        "3babcf62-2d0e-3952-bb4c-b90f73cd1ebe", "", 0), "luibara2"));
        check("accepts an IPv6 literal",
                accepted(validate, extension, body("luibara2", "2535459084817261",
                        "3babcf62-2d0e-3952-bb4c-b90f73cd1ebe", "2001:db8::1", 25565), "luibara2"));

        if (failures > 0) {
            throw new AssertionError(failures + " geyser validation check(s) failed");
        }
        System.out.println("all geyser validation checks passed");
    }

    private static String body(String name, String xuid, String uuid, String realIp, int realPort) {
        return "{\"status\":\"ok\",\"name\":\"" + name + "\",\"xuid\":\"" + xuid + "\",\"uuid\":\""
                + uuid + "\",\"backend\":\"skygen\",\"real_ip\":\"" + realIp + "\",\"real_port\":"
                + realPort + "}";
    }

    private static boolean accepted(Method validate, EndlinkGuardExtension extension,
                                    String body, String requestedName) throws Exception {
        Object result = validate.invoke(extension, body, requestedName);
        Method ok = result.getClass().getDeclaredMethod("accepted");
        ok.setAccessible(true);
        return (boolean) ok.invoke(result);
    }

    private static void check(String description, boolean condition) {
        if (condition) {
            System.out.println("  ok   " + description);
        } else {
            System.out.println("  FAIL " + description);
            failures++;
        }
    }
}
