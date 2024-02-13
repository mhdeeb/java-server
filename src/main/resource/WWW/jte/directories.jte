@import java.io.File
@import java.nio.file.Path
@import org.mhdeeb.server.Server
@import org.mhdeeb.server.Util

@param File directory

!{
    Path relativeDirectoryPath = Server.getRootDirectory().relativize(directory.toPath());
    String relativeDirectoryString = Util.cleanPath(relativeDirectoryPath.toString());
    String relativeDirectoryImageString = Util.cleanPath(Server.getRootDirectory().relativize(Server.getImage("folder.svg")).toString());
    String relativeFileImageString = Util.cleanPath(Server.getRootDirectory().relativize(Server.getImage("file.svg")).toString());
    String relativeParentImageString = Util.cleanPath(Server.getRootDirectory().relativize(Server.getImage("undo.svg")).toString());
}

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Index /${relativeDirectoryString}</title>
    </head>
    <body>
        <h1>Index of /${relativeDirectoryString}</h1>
        <table>
            <thead>
                    <tr>
                        <th>
                        </th>
                        <th>
                            <a href="?C=N&O=A">Name</a>
                        </th>
                        <th>
                            <a href="?C=M&O=A">Last Modified</a>
                        </th>
                        <th>
                            <a href="?C=S&O=A">Size</a>
                        </th>
                        <th>
                            <a href="?C=S&O=D">Download</a>
                        </th>
                    </tr>
            </thead>
            <tbody>
                    <tr>
                        <th colspan="5">
                            <hr>
                        </th>
                    </tr>
                @if(relativeDirectoryString.length() > 0)
                    <tr>
                        <td valign="top">
                            <img src="/${relativeParentImageString}" alt="[BACK]" width="20" height="22">
                        </td>
                        <td>
                            <a href="/${relativeDirectoryPath.getParent() == null ? "" : relativeDirectoryPath.getParent().toString()}">Parent Directory</a>
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
                            <td style="padding: 0 15px; text-align: center;">
                                ${Util.millisecondsToDateString(d.lastModified())}
                            </td>
                            <td style="padding: 0 15px; text-align: center;">
                                ${Util.sizeToString(Util.getFolderSize(d))}
                            </td>
                            <td style="text-align: center;">
                                <a href="/${relative.toString()}?zip" download>Zip</a>
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
                            <td style="padding: 0 15px; text-align: center;">
                                ${Util.millisecondsToDateString(file.lastModified())}
                            </td>
                            <td style="padding: 0 15px; text-align: right;">
                                ${Util.sizeToString(file.length())}
                            </td>
                            <td style="text-align: center;">
                                <a href="/${relative.toString()}" download>Download</a>
                            </td>
                        </tr>
                    @endfor
                @endif
                    <tr>
                        <th colspan="5">
                            <hr>
                        </th>
                    </tr>
            </tbody>
        </table>
    </body>
</html>