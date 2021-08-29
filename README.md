 
# stella
 
ステラは、CLIのマルウェア表層解析ツールです。<br>
Windowsマルウェアの実行ファイル(.exe)を表層解析します。<br>
ハッシュ値、VirusTotal・HybridAnalysisへのリンク<br>
また、linuxのstringsコマンドを使用して各メソッドごとに分類、どんな挙動をするのかを特定します。<br>
特に怪しい挙動を示す文字列はblacklistとして、赤で表示します。<br>
<img src="https://user-images.githubusercontent.com/72499679/130217115-7c5a4e03-a8c5-48e4-a184-a8ad12d35682.png" width=500>
 
 
stellaのインストール方法(debian系・Ubuntu系
ターミナルで
<pre><code>
sudo apt-get install binutils
</pre></code>
<pre><code>
sudo apt-get install xxd
</pre></code>
<pre><code>
sudo apt-get install file
</pre></code>
<pre><code>
sudo apt update && sudo apt upgrade
</pre></code>

任意のディレクトリに移動して

<pre><code>
wget "https://github.com/crum7/Stella/raw/main/stella01"
</pre></code>
<pre><code>
chmod 777 stella
</code></pre>

使用方法<br>
$ ./stella 〇〇.exe<br>
ずらっと表示されます。<br>
<br>
<br>

 
stringsコマンドは難読化されたファイルので読み取りはできないので、Flossツールを用いたものも用意しました。<br>
<a href="https://github.com/fireeye/flare-floss">floss</a>
これは、flossとstellaを同じディレクトリに置くことが必要です。
 
stella_flossver(stellaf)のインストール方法(debian系・Ubuntu系

<pre><code>
sudo apt-get install binutils
</code></pre>
<pre><code>
sudo apt-get install xxd
</code></pre>
<pre><code>
sudo apt-get install file
</code></pre>
<pre><code>
sudo apt-get upgrade
</code></pre>
任意のディレクトリに移動して
 
flossのインストール
<pre><code>
wget "https://github.com/fireeye/flare-floss/releases/download/v1.7.0/floss-v1.7.0-linux.zip"
</code></pre>
<pre><code>
unzip floss-v1.7.0-linux.zip
</code></pre>
<pre><code>
wget "https://github.com/crum7/stella/raw/main/stellaf01"
</code></pre>
<pre><code>
chmod 777 floss
</code></pre>
<pre><code>
chmod 777 stellaf
</code></pre>


使用方法<br>
$ ./stella 〇〇.exe<br>
stellaに比べると少し実行速度が遅いです。<br>
<br><br>
---------------------------更新<br>
./stella01と./stellaf01では、httpに関係するstringsを表示するようにしました。<br>
ランサムウェアの可能性を判断するようにしました。<br>

