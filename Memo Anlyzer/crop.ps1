Add-Type -AssemblyName System.Drawing
=[System.Drawing.Image]::FromFile('C:\Users\Jhon\AppData\Local\Temp\qoder-computer-use-images\1341559d\img-1788153197624015700-058298.png')
=New-Object System.Drawing.Rectangle(880,80,562,60)
=.Clone(,.PixelFormat)
.Save('e:\Memo Anlyzer\crop_toolbar.png')
=New-Object System.Drawing.Rectangle(0,130,270,180)
=.Clone(,.PixelFormat)
.Save('e:\Memo Anlyzer\crop_tree.png')
.Dispose()
Write-Output done
