 
# stella


ステラは、CUIのマルウェア表層解析ツールです。<br>
![image](https://user-images.githubusercontent.com/72499679/145970551-f61db31d-63f3-4b66-817c-0851755b48f0.png)
<br>
-----特徴-----<br>
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

難読化されたマルウェアの読み取りも可能するためにstella_2.0ではflossも内包しました。<br>
<a href="https://github.com/fireeye/flare-floss">floss</a>
 <br>
 <br>

-----stella2.0のインストール-----<br>
<code>
 sudo su -
</code>
<code>
 wget https://github.com/crum7/Stella/raw/main/install.sh
 </code>
<code>
 chmod 777 install.sh
</code>
 <br>
<code>
./install.sh
</code>
<br>
インストール完了<br>

-----使用方法-----<br>
stellaの場合<br>
$ ./stella 〇〇.exe<br>
ずらっと表示されます。<br>
<br>
<br>
<br>
stella2.0の場合<br>
$ stella 〇〇.exe<br>
対話形式で始まるので、最初はhを入力してコマンドの一覧を確認してください。<br>
/usr/local/binに置いているので、ディレクトリなどを気にせず利用できます。<br>
rコマンドであまり出てこない場合は、fコマンドを使用してください。
コマンドを打ち間違えた場合は、hコマンドで元に戻れます。
<br>
<br>
<br>
---------------------------stella更新<br>
./stellaと./stellaf01では、httpに関係するstringsを表示するようにしました。<br>
ランサムウェアの可能性を判断するようにしました。<br>
<img src="https://user-images.githubusercontent.com/72499679/130217115-7c5a4e03-a8c5-48e4-a184-a8ad12d35682.png" width=500>

---------------------------stella2.0更新<br>
./stellaと./stellaf01では、httpに関係するstringsを表示するようにしました。<br>
ランサムウェアの可能性を判断するようにしました。<br>
flossを組み込んだため、柔軟に表層解析に取り組むことができます。<br>
対話形式になったことで、自分の見たい情報のみを表示させることができます。<br>
1つのマルウェアの表層解析をしながら、別のマルウェアの表層解析を表示することができます。<br>
![image](https://user-images.githubusercontent.com/72499679/145953437-6f0074ce-d29b-4573-a649-7b6f6130ed47.png)

