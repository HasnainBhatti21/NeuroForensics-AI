Add-Type -AssemblyName System.Drawing
$src = 'C:\Users\Jhon\AppData\Local\Temp\qoder-computer-use-images\8f5d5fec\img-1788192367536364200-839933.png'
$out = 'e:\Memo Anlyzer\inspection'
$img = [System.Drawing.Image]::FromFile($src)
function Crop($name,$x,$y,$w,$h){
  $rect = New-Object System.Drawing.Rectangle $x,$y,$w,$h
  $bmp = ([System.Drawing.Bitmap]$img).Clone($rect, $img.PixelFormat)
  $big = New-Object System.Drawing.Bitmap ($w*2),($h*2)
  $g = [System.Drawing.Graphics]::FromImage($big)
  $g.InterpolationMode = 'NearestNeighbor'
  $g.DrawImage($bmp, 0, 0, ($w*2), ($h*2))
  $g.Dispose()
  $big.Save("$out\$name.png")
  $big.Dispose(); $bmp.Dispose()
}
Crop 'tabs' 0 150 1000 100
Crop 'form_top' 0 250 700 200
Crop 'form_bottom' 0 440 700 180
Crop 'card_bottom' 0 580 1442 90
$img.Dispose()
