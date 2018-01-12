import java.io.BufferedReader;
import java.io.InputStreamReader;

public class FilterTest {

	public static void main(String[] args) throws Exception {
		// Sun's ProcessBuilder and Process example
		ProcessBuilder pb = new ProcessBuilder("ls", "-l", "/tmp");
		Process p = pb.start();
		BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
		while (br.ready()) {
			System.out.println(br.readLine());
		}
		br.close();
		System.out.println("Done: " + p.waitFor());
		
		SystemCallFilter.init();
		
		p = pb.start();
		br = new BufferedReader(new InputStreamReader(p.getInputStream()));
		while (br.ready()) {
			System.out.println(br.readLine());
		}
		br.close();
		System.out.println("Done: " + p.waitFor());
	}

}
