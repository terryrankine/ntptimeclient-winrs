param($f)
$v = Get-Content $f | Where-Object { $_ -match '^\d\d:\d\d:\d\d, ([+-][\d.]+)s' } | ForEach-Object { [double]$Matches[1] }
$s = $v | Sort-Object; $n = $s.Count
$med = ($s[[int](($n-1)/2)] + $s[[int]($n/2)])/2
$ma = ($v | ForEach-Object { [math]::Abs($_) } | Measure-Object -Average).Average
"n=$n min=$($s[0]) max=$($s[-1]) median=$med meanabs=$ma"
