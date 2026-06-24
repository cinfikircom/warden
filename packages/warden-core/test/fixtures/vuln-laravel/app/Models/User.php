<?php
namespace App\Models;
use Illuminate\Database\Eloquent\Model;
class User extends Model {
    protected $guarded = [];
    public function email() { return $this->attributes['email']; }
}
