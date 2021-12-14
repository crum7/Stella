 
# stella
 
ステラは、CUIのマルウェア表層解析ツールです。<br>
![image](https://user-images.githubusercontent.com/72499679/145947876-890c6290-eb18-4b5c-b96d-5825a5f24177.png)<br>
-----特徴-----
Windowsマルウェアの実行ファイル(.exe)を表層解析をします。<br>
各マルウェアのハッシュ値<br>
md5sum<br>
sha256sum<br>
sha1sum<br>
を算出し、表示します。<br>
また、このマルウェアのハッシュ値を使用して、有効なVirusTotal・HybridAnalysisへのリンクを表示します。<br>
![image](https://user-images.githubusercontent.com/72499679/145953125-99fed885-bfa9-44be-b8ea-070dfe3e7ba2.png)<br>


そして、マルウェアのバイナリの中の可読部を各メソッドごとに分類、どんな挙動をするのかを特定します。<br>
![image](https://user-images.githubusercontent.com/72499679/145953193-fd97f016-2527-42b9-969f-9ec8aac9315c.png)<br>

特に深刻な影響・マルウェアの特徴が現れている部分を示す文字列はblacklistとしてまとめ、表示します。<br>
![image](https://user-images.githubusercontent.com/72499679/145953303-2db367fb-1033-4e3a-8461-7aaa2b966869.png)<br>
<br>



 
 <br>
 <br>
stellaのインストール方法(debian系・Ubuntu系<br>
stella1.0(一覧表示)とstella2.0（対話形式)を選択してインストールしてください。<br>
初めて使用する方は、stella2.0が使いやすいと思います。<br>
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

 
難読化されたファイルので読み取りはできないので、Flossツールを用いたものも用意しました。<br>
<a href="https://github.com/fireeye/flare-floss">floss</a>
これは、flossとstellaを同じディレクトリに置くことが必要です。
<br>
<br>
<br>
---------------------------stella更新<br>
./stellaと./stellaf01では、httpに関係するstringsを表示するようにしました。<br>
ランサムウェアの可能性を判断するようにしました。<br>
<img src="https://user-images.githubusercontent.com/72499679/130217115-7c5a4e03-a8c5-48e4-a184-a8ad12d35682.png" width=500>

---------------------------stella2.0更新<br>
対話形式になったことで、自分の見たい情報のみを表示させることができます。
1つのマルウェアの表層解析をしながら、別のマルウェアの表層解析を表示することができます。
![image](https://user-images.githubusercontent.com/72499679/145953437-6f0074ce-d29b-4573-a649-7b6f6130ed47.png)

