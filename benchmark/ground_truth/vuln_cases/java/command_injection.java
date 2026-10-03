public class Pinger {
    public Process ping(String host) throws Exception {
        return Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
