<?php
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;
class CardController {
    public function hashPw($pw) { return md5($pw); }
    public function find($id) {
        return DB::select("SELECT * FROM users WHERE id = " . $id);
    }
    public function run($name) { return shell_exec("report " . $name); }
    public function store($card_number, $cvv) {
        DB::table('cards')->insert(['card_number' => $card_number, 'cvv' => $cvv]);
    }
    public function all() { return \App\Models\User::withoutGlobalScopes()->get(); }
}
