 
# stella
 
ステラは、CUIのマルウェア表層解析ツールです。<br>

-----特徴-----
Windowsマルウェアの実行ファイル(.exe)を表層解析します。<br>
ハッシュ値、VirusTotal・HybridAnalysisへのリンク<br>
また、linuxのstringsコマンドを使用して各メソッドごとに分類、どんな挙動をするのかを特定します。<br>
特に怪しい挙動を示す文字列はblacklistとして、赤で表示します。<br>

![image](https://user-images.githubusercontent.com/72499679/145947876-890c6290-eb18-4b5c-b96d-5825a5f24177.png)


 
 <br>
 <br>
stellaのインストール方法(debian系・Ubuntu系
<br>
<code>
 chmod 777 install.sh
</code>
 <br>
<code>
./install.sh
</code>
<br>

使用方法<br>
$ ./stella 〇〇.exe<br>
ずらっと表示されます。<br>
<br>
<br>

 
stringsコマンドは難読化されたファイルので読み取りはできないので、Flossツールを用いたものも用意しました。<br>
<a href="https://github.com/fireeye/flare-floss">floss</a>
これは、flossとstellaを同じディレクトリに置くことが必要です。
<br>

---------------------------stella更新<br>
./stellaと./stellaf01では、httpに関係するstringsを表示するようにしました。<br>
ランサムウェアの可能性を判断するようにしました。<br>
<img src="https://user-images.githubusercontent.com/72499679/130217115-7c5a4e03-a8c5-48e4-a184-a8ad12d35682.png" width=500>

---------------------------stella2.0更新<br>
対話形式になったことで、自分の見たい情報のみを表示させることができます。
1つのマルウェアの表層解析をしながら、別のマルウェアの表層解析を表示することができます。

