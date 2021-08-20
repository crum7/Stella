 
# stella
 
ステラは、CLIのマルウェア表層解析ツールです。
Windowsマルウェアの実行ファイル(.exe)を表層解析します。
ハッシュ値、VirusTotal・HybridAnalysisへのリンク。
また、linuxのstringsコマンドを使用して各メソッドごとに分類、どんな挙動をするのかを特定します。
特に怪しい挙動を示す文字列はblacklistとして、赤で表示します。
(https://user-images.githubusercontent.com/72499679/130216979-f5b50119-fc9e-4271-a0b6-ff82a8cd7208.png)
(https://user-images.githubusercontent.com/72499679/130217115-7c5a4e03-a8c5-48e4-a184-a8ad12d35682.png)
 
 
stellaのインストール方法(debian系

$ sudo apt-get install binutils
$ sudo apt-get install xxd
$ sudo apt-get install file
$ sudo apt update && sudo apt upgrade
~任意のディレクトリに移動して~
 
$ wget "https://github.com/crum7/stella/raw/main/stella"
$ chmod 777 stella
 
使用方法
$ ./stella 〇〇.exe
ずらっと表示されます。


 
stringsコマンドは難読化されたファイルので読み取りはできないので、Flossツールを用いたものも用意しました。
これは、flossとstellaを同じディレクトリに置くことが必要です。
 
stella_flossver(stellaf)のインストール方法(debian系
$ sudo apt-get install binutils
$ sudo apt-get install xxd
$ sudo apt-get install file
$ sudo apt-get upgrade
~任意のディレクトリに移動して~
 
flossのインストール
$ wget "https://github.com/fireeye/flare-floss/releases/download/v1.7.0/floss-v1.7.0-linux.zip"
$ unzip floss-v1.7.0-linux.zip
$ wget "https://github.com/crum7/stella/raw/main/stellaf"
$ chmod 777 floss
$ chmod 777 stellaf

使用方法
$ ./stella 〇〇.exe
stellaに比べると少し実行速度が遅いです。



