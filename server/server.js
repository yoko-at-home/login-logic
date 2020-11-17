//他のファイルでも必要とする前提となる情報を盛り込んでいる
//require('dotenv').config()は次のようにもできる
const dotenv = require("dotenv");
dotenv.config();
// サーバーの指定のみを実行(package.jsonから最初に読み込まれる)
const app = require("./app");
const port = 4000;

app.listen(port, () => {
  console.log('ポート4000が開きました❤️')
});
