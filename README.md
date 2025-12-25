# list2hosting
las(点群データ)をMinecraft Bedrockのローカルワールドに送信するものです。

またMinecraft Bedrockで、/connectコマンド又は/wsコマンドで接続できるサーバーを作成します。

# 使用方法
## ビルドバイナルを使う方法

1. まず最新のリリースから.exeやBinaryをダウンロードします。
2. ダウンロードしたBinaryを実行します。
3. コマンドプロンプト又はターミナルが出てきたら、```start [port番号]```を入力してWSサーバーを起動します。
   ※```list2hosting>```とコンソールで出ている場合に行ってください。成功した場合は```INF Server is ready on port [ここに実際のポート番号]```と表示されます。
   ※ワールド側でチートをONにする必要があります。
4. WSサーバーが起動したら、Minecraft側で```/connect [serverIP:serverPort]```を入力し、○○に接続しましたと出力されたら準備は完了です。Console側では、```[2025-12-25 10:17:18] INF Client connected: [ClientIP:ClientPort]```と```WebSocket handshake OK!```のように出力されます。
5. あとはお好みのコマンドを実行できます。

## ソースコードからビルドする方法

1. ソースを.zip又は、```git clone https://github.com/androidprod/list2hosting.git```とコマンドを実行し、ソースコードダウンロードします。
2. cmakeをインストールされていることを確認し、```.\build.bat```又はLinuxではchmodで許可してから```./build.sh```を実行しビルドします。
3. ```./build/Release```又は、```./build/```のなかにBinaryがあれば成功です。
   ※ここからは上記の実行方法と同じです。
4. 生成されたBinaryを実行します。
5. コマンドプロンプト又はターミナルが出てきたら、```start [port番号]```を入力してWSサーバーを起動します。
   ※```list2hosting>```とコンソールで出ている場合に行ってください。成功した場合は```INF Server is ready on port [ここに実際のポート番号]```と表示されます。
   ※ワールド側でチートをONにする必要があります。
6. WSサーバーが起動したら、Minecraft側で```/connect [serverIP:serverPort]```を入力し、○○に接続しましたと出力されたら準備は完了です。Console側では、```[2025-12-25 10:17:18] INF Client connected: [ClientIP:ClientPort]```と```WebSocket handshake OK!```のように出力されます。
7. あとはお好みのコマンドを実行できます。


# 作成者 
androidprod
