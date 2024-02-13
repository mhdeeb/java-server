@import java.io.File
@import java.nio.file.Path
@import org.mhdeeb.server.Server
@import org.mhdeeb.server.Util

@param Path relativeDirectoryPath
@param String relativeDirectoryString
@param String relativeDirectoryImageString
@param String relativeFileImageString
@param String relativeParentImageString
@param File[] files
@param String[] ordering


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
                            <a href="?C=N&O=${ordering[0]}">Name</a>
                        </th>
                        <th>
                            <a href="?C=M&O=${ordering[1]}">Last Modified</a>
                        </th>
                        <th>
                            <a href="?C=S&O=${ordering[2]}">Size</a>
                        </th>
                        <th>
                            <a href="?C=D&O=${ordering[3]}">Download</a>
                        </th>
                    </tr>
            </thead>
            <tbody>
                    <tr>
                        <th colspan="5">
                            <hr>
                        </th>
                    </tr>
                @if(!relativeDirectoryString.isEmpty())
                    <tr>
                        <td valign="top">
                            <img src="/${relativeParentImageString}" alt="[BACK]" width="20" height="22">
                        </td>
                        <td>
                            <a href="/${relativeDirectoryPath.getParent() == null ? "" : relativeDirectoryPath.getParent().toString()}">Parent Directory</a>
                        </td>
                    </tr>
                @endif
                @if(files != null)
                    @for(File file : files)
                        !{Path relative = Server.getRootDirectory().relativize(file.toPath());}
                        @if(file.isDirectory())
                        <tr>
                            <td valign="top">
                                <img src="/${relativeDirectoryImageString}" alt="[DIR]" width="20" height="22">
                            </td>
                            <td>
                                <a href="/${relative.toString()}">${relative.getFileName().toString()}/</a>
                            </td>
                            <td style="padding: 0 15px; text-align: center;">
                                ${Util.millisecondsToDateString(file.lastModified())}
                            </td>
                            <td style="padding: 0 15px; text-align: center;">
                                ${Util.sizeToString(Util.getFolderSize(file))}
                            </td>
                            <td style="text-align: center;">
                                <a href="/${relative.toString()}?zip" download>Zip</a>
                            </td>
                        </tr>
                        @else
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
                        @endif
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