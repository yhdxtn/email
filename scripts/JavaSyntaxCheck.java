import java.nio.file.*;
import java.util.*;
import javax.tools.*;
import com.sun.source.util.JavacTask;
/** Parses source using javac without symbol resolution. Not a dependency/type compilation. */
public class JavaSyntaxCheck {
    public static void main(String[] args)throws Exception{
        var compiler=ToolProvider.getSystemJavaCompiler();var diagnostics=new DiagnosticCollector<JavaFileObject>();
        try(var files=compiler.getStandardFileManager(diagnostics,null,null);var walk=Files.walk(Path.of(args[0]))){
            var paths=walk.filter(p->p.toString().endsWith(".java")).toList();
            var task=(JavacTask)compiler.getTask(null,files,diagnostics,List.of("--release","21","-proc:none"),null,files.getJavaFileObjectsFromPaths(paths));
            for(var ignored:task.parse()){}
            var errors=diagnostics.getDiagnostics().stream().filter(d->d.getKind()==Diagnostic.Kind.ERROR).toList();
            errors.forEach(System.err::println);if(!errors.isEmpty())System.exit(1);
            System.out.println("PASS: javac parsed "+paths.size()+" Java source files; dependency/type checking NOT performed");
        }
    }
}
