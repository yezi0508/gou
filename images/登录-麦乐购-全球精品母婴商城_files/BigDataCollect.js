function comgoucctv() {
	this._uid = 0;
	this._refferUrl = document.referrer;
	this._refferHost = "";
	this._gid = 0;
	this._storeType = 0;
	this._storeId = 0;
	this._sid = null;
	this._pid = 0;
	this._currurl = document.location.href;
	this._currurlHost = document.location.host;
	this._eid = 0;
	this._gprice = 0.00;
	this._oid = 0;
	this._currtotal = 0.00;
	this._cookiename = "comgoucollectcid";
	this._cookieuid = "M6goDataCollectPid";
	this._rootdomain = document.domain.split('.').slice(-2).join('.');
}

comgoucctv.prototype = {
	sk: function(name, value) {
		try {
			var nowDate = new Date();
			nowDate.setMonth(nowDate.getMonth() + 12);
			document.cookie = name + "=" + value + ";expires=" + nowDate.toGMTString() + ";Path=/;domain=" + this._rootdomain;
		} catch (e) {
			//e.message
		}
	},
	gk: function(name) {
		try {
			var cookievalue = document.cookie;
			var startposition = cookievalue.indexOf("" + name + "=");
			if (startposition == -1) {
				cookievalue = null;
			} else {
				startposition = cookievalue.indexOf("=", startposition) + 1;
				var endposition = cookievalue.indexOf(";", startposition);
				if (endposition == -1) {
					endposition = cookievalue.length;
				}
				cookievalue = unescape(cookievalue.substring(startposition, endposition));
			}
			return cookievalue;
		} catch (e) {
			return null;
		}
	},
	dk: function(name) {
		try {
			var nowDate = new Date();
			nowDate.setTime(nowDate.getTime() - 10000);
			document.cookie = name + "=v;expires=" + nowDate.toGMTString();
		} catch (e) {
			//e.message
		}
	},
	nc: function() {
		try {
			var chars = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];
			var res = "";
			for (var i = 0; i < 20; i++) {
				var id = Math.ceil(Math.random() * 35);
				res += chars[id];
			}
			return res;
		} catch (e) {
			return Math.random() * 24;
		}
	},
	sm: function() {
		try {
			this._uid = this.gk(this._cookieuid);
			if (this._uid == "" || this._uid == null) {
				this._uid = 0;
			}
			if (this._refferUrl != "" && this._refferUrl != null) {
				var parser = document.createElement('a');
				parser.href = this._refferUrl;
				this._refferHost = parser.host;
			}
			this._sid = this.gk(this._cookiename);
			if (this._sid == "" || this._sid == null) {
				this._sid = this.nc();
				this.sk(this._cookiename, this._sid);
			}
			if (this._currurl.toLowerCase().indexOf("/mycart.do") > -1) {
				this._pid = -100;
			}
		} catch (e) {
			//e.message
		}
	},
	ra: function() {
		try {
			if (this._pid > 0) {
				var values = '{"position":"' + this._pid + '","positionNo":"0","productId":"0","price":"0.00"}';
				jQuery.cookie("productHrefLink", values, {
					path: '/',
					domain: this._rootdomain
				});
			}

			jQuery.ajax({
				url: "http://collect.gou.com/api/collect?rnd=" + Math.random(),
				type: "POST",
				async: true,
				dataType: "json",
				data: {
					UserId: this._uid,
					RefferUrl: this._refferUrl,
					RefferHost: this._refferHost,
					GoodsId: this._gid,
					StoreType: this._storeType,
					StoreId: this._storeId,
					SessionId: this._sid,
					PositionId: this._pid,
					CurrUrl: this._currurl,
					CurrHost: this._currurlHost,
					EquipmentId: this._eid,
					CurrGoodsPrice: this._gprice,
					CurrOrderId: this._oid,
					CurrTotal: this._currtotal
				},
				jsonp: "callback",
				jsonpCallback: "searchHandler",
				success: function(response) {
					//do nothing
				},
				error: function() {
					//error
				}
			});
		} catch (e) {
			//e.message
		}
	}
}

try {
	var m = new comgoucctv;
	m.sm();
	m.ra();
} catch (e) {
	//e.message
}

function HitsPosition(PositionId, GoodsId, StoreType, StoreId) {
	HitsPosition_up(PositionId, GoodsId, StoreType, StoreId, 0, 0, 0);
}

function HitsPosition_up(PositionId, GoodsId, StoreType, StoreId, CurrGoodsPrice, CurrOrderId, CurrTotal) {
	try {
		var m = new comgoucctv;
		m.sm();
		m._pid = PositionId;
		m._gid = GoodsId;
		m._storeType = StoreType;
		m._storeId = StoreId;
		m._gprice = CurrGoodsPrice;
		m._oid = CurrOrderId;
		m._currtotal = CurrTotal;
		m.ra();
	} catch (e) {
		//e.message
	}
}