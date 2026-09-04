Add-Type -AssemblyName System.Drawing
$src = 'C:\Users\Jhon\AppData\Local\Temp\qoder-computer-use-images\8f5d5fec\img-1788192794355809100-030031.png'
$img = [System.Drawing.Image]::FromFile($src)
$rect = New-Object System.Drawing.Rectangle 0,270,800,60
$bmp = ([System.Drawing.Bitmap]$img).Clone($rect, $img.PixelFormat)
$big = New-Object System.Drawing.Bitmap 1600,120
$g = [System.Drawing.Graphics]::FromImage($big)
$g.InterpolationMode = 'NearestNeighbor'
$g.DrawImage($bmp, 0, 0, 1600, 120)
$g.Dispose()
$big.Save('e:\Memo Anlyzer\inspection\lookin.png')
$big.Dispose(); $bmp.Dispose(); $img.Dispose()
