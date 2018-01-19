import java.io.BufferedReader;
import java.io.InputStreamReader;

public class FilterTest {

	public static void main(String[] args) throws Exception {

		ProcessBuilder pb = new ProcessBuilder("cmd", "/c", "dir", "c:\\");
		Process p = pb.start();
		BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
		while (br.ready()) {
			System.out.println(br.readLine());
		}
		br.close();
		System.out.println("Done: " + p.waitFor());

		SystemCallFilter.main(null);

		p = pb.start();
		br = new BufferedReader(new InputStreamReader(p.getInputStream()));
		while (br.ready()) {
			System.out.println(br.readLine());
		}
		br.close();
		System.out.println("Done: " + p.waitFor());
	}

}
