import java.io.BufferedReader;
import java.io.InputStreamReader;

public class FilterTest {

	public static void main(String[] args) throws Exception {

		ProcessBuilder pb = new ProcessBuilder("cmd", "/c", "dir");
		Process p = pb.start();
		BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
		String line;
		while ((line = br.readLine()) != null) {
			System.out.println(line);
		}
		br.close();
		System.out.println("Done: " + p.waitFor());

		SystemCallFilter.main(null);

		p = pb.start();
		br = new BufferedReader(new InputStreamReader(p.getInputStream()));
		while ((line = br.readLine()) != null) {
			System.out.println(line);
		}
		br.close();
		System.out.println("Done: " + p.waitFor());
	}

}
