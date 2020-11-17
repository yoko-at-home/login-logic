const { Pool } = require("pg");
const pool = new Pool();
// {
//デーベースの情報を入れる=> .envファイルに移行posgreは書かなくても大丈夫
// user: "postgres", //デフォルト
// host: "localhost", //デフォルト
// database: "mercari",
// password: "password", //デフォルト
// port: 5432, //posgres専用ポートのデフォルト
// }

//pool.query("select * from item"); =>以下のようにエクスポートした先で使う
//参照サイト：node-posgres.com （pg pooling...Kenさんから情報くる）
module.exports = {
  query: (text, params, callback) => {
    return pool.query(text, params, callback);
  },
};
