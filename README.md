 
# stella


ステラは、Linux専用のCUIのマルウェア表層解析ツールです。<br>
![image](https://user-images.githubusercontent.com/72499679/158712420-555d03f4-9b07-4c98-911c-f1420bf39503.png)

<br>
-----特徴-----<br>
Windowsマルウェアの実行ファイル(.exe)を表層解析をします。<br>
各マルウェアのハッシュ値<br>
md5sum<br>
sha256sum<br>
sha1sum<br>
を算出し、表示します。<br>
また、このマルウェアのハッシュ値を使用して、有効なVirusTotal・HybridAnalysisへのリンクを表示します。<br>
![image](https://user-images.githubusercontent.com/72499679/158713007-0edb873c-ee0a-46ce-8c67-127cbbad7c31.png)
<br>


そして、マルウェアのバイナリの中の可読部を各メソッドごとに分類、どんな挙動をするのかを特定します。<br>
![image](https://user-images.githubusercontent.com/72499679/158713070-fc3abe56-ded2-4620-be1c-508090cab1dd.png)
<br>

特に深刻な影響・マルウェアの特徴が現れている部分を示す文字列はblacklistとしてまとめ、表示します。<br>
![image](https://user-images.githubusercontent.com/72499679/158713122-51e9de2a-9d9a-48bf-8ed8-adb876362923.png)
<br>
<br>

難読化されたマルウェアの読み取りも可能するためにstella_2.0ではflossも内包しました。<br>
<a href="https://github.com/fireeye/flare-floss">floss</a>
 <br>
 <br>

-----stellaのインストール-----<br>
<code>
 sudo su -
</code><br>
<code>
 wget https://github.com/crum7/Stella/raw/main/install.sh
 </code><br>
<code>
 chmod 777 install.sh
</code><br>
<code>
./install.sh
</code><br>
インストール完了<br>

-----使用方法-----<br>
$ stella 〇〇.exe<br>
<br>
コマンド      使い方<br>
h      ヘルプ<br>
i      基本的な情報<br>
q      終了<br>
r      全体の調査結果<br>
b      ブラックリスト<br>
c      clear<br>
ls     lsコマンド<br>
n      他のマルウェアの解析<br>
f      flossツールを使った全体の調査結果<br>
z      flossツールを使ったブラックリスト<br>
<br>
対話形式で始まるので、最初はhを入力してコマンドの一覧を確認してください。<br>
/usr/local/binに置いているので、ディレクトリなどを気にせず利用できます。<br>
rコマンドであまり出てこない場合は、fコマンドを使用してください。
コマンドを打ち間違えた場合は、hコマンドで元に戻れます。



<br>
<br>
<br>

./stellaと./stellaf01では、httpに関係するstringsを表示するようにしました。<br>
ランサムウェアの可能性を判断するようにしました。<br>
<img src="https://user-images.githubusercontent.com/72499679/130217115-7c5a4e03-a8c5-48e4-a184-a8ad12d35682.png" width=500>

---------------------------stella更新<br>
./stellaと./stellaf01では、httpに関係するstringsを表示するようにしました。<br>
ランサムウェアの可能性を判断するようにしました。<br>
flossを組み込んだため、柔軟に表層解析に取り組むことができます。<br>
対話形式になったことで、自分の見たい情報のみを表示させることができます。<br>
1つのマルウェアの表層解析をしながら、別のマルウェアの表層解析を表示することができます。<br>
![image](https://user-images.githubusercontent.com/72499679/158713197-d90d84df-3770-4722-b4f1-13250d3c7289.png)


