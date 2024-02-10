		

@import java.io.File
@import java.nio.file.Path
@import org.mhdeeb.server.Server

@param File directory

!{
    Path relativeDirectoryPath = Server.getRootDirectory().relativize(directory.toPath());
    String relativeDirectoryString = relativeDirectoryPath.toString().replace("&bsol;", "/");
    String relativeDirectoryImageString = Server.getRootDirectory().relativize(Server.getImage("folder.svg")).toString().replace("&bsol;", "/");
    String relativeFileImageString = Server.getRootDirectory().relativize(Server.getImage("file.svg")).toString().replace("&bsol;", "/");
    String relativeParentImageString = Server.getRootDirectory().relativize(Server.getImage("undo.svg")).toString().replace("&bsol;", "/");
}

<!DOCTYPE html>
<html lang="en">
    <head
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Index /${relativeDirectoryString}</title>
    </head>
    <body>
        <h1>Index of /${relativeDirectoryString}</h1>
        <table>
            <tbody>
                @if(relativeDirectoryString.length() > 0)
                    <tr>
                        <td valign="top">
                            <img src="/${relativeParentImageString}" alt="[BACK]" width="20" height="22">
                        </td>
                        <td>
                            <a href="/${relativeDirectoryPath.getParent() == null ? "" : relativeDirectoryPath.getParent().toString()}">../</a>
                        </td>
                    </tr>
                @endif
                !{File[] directories = directory.listFiles(File::isDirectory);}
                @if(directories != null)
                    @for(File d : directories)
                        !{Path relative = Server.getRootDirectory().relativize(d.toPath());}
                        <tr>
                            <td valign="top">
                                <img src="/${relativeDirectoryImageString}" alt="[DIR]" width="20" height="22">
                            </td>
                            <td>
                                <a href="/${relative.toString()}">${relative.getFileName().toString()}/</a>
                            </td>
                        </tr>
                    @endfor
                @endif
                !{File[] files = directory.listFiles(File::isFile);}
                @if(files != null)
                    @for(File file : files)
                        !{Path relative = Server.getRootDirectory().relativize(file.toPath());}
                        <tr>
                            <td valign="top">
                                <img src="/${relativeFileImageString}" alt="[FILE]" width="20" height="22">
                            </td>
                            <td>
                                <a href="/${relative.toString()}">${relative.getFileName().toString()}/</a>
                            </td>
                        </tr>
                    @endfor
                @endif
            </tbody>
        </table>
    </body>
</html>