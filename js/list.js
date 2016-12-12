/*window.onload=function(){
	var nav=document.getElementById('nav');
	console.log(nav);
	var menu_list=document.getElementById('menu-list');
	var menu_list_lis=menu_list.getElementsByTagName('li');
	var submenu_boxs=document.querySelectorAll('.submenu-box');
	console.log(menu_list);
	console.log(menu_list_lis);
	console.log(submenu_boxs);
	for(var i=0;i<menu_list_lis.length;i++){
		menu_list_lis[i].index=i;
		menu_list_lis[i].onmouseover=function(){
			for(var j=0;j<menu_list_lis.length;j++){
				var menu_list_lis_index=this.index;
				//alert(this.index);
				var submenu_boxs_index=menu_list_lis_index;

			}
			submenu_boxs[this.index].display="block";
		}
	}
}*/