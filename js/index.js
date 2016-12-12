/*ad部分*/
//获取元素
/*window.onload=function(){
var ad =document.getElementById('ad');
console.log(ad);
var closebtn=document.getElementById('closebtn');
console.log(closebtn);*/
$(function(){
	//点击按钮的时候让其父母消失
	$('#closebtn').click(function(){
		$(this).parent().animate({
			opacity:0
		},400,function(){
			$(this).hide();
		});
	});

	/*	$(this).parent().css({
			opacity:0
		}).on('transitionend',function(){
			$(this).height(0);
		});*/
		/*$(this).parent().animate({
			opacity:0
		},500,function(){
			$(this).hide();
		});*/
		//$(this).parent().hide();

	//鼠标移上的时候，显示，鼠标离开隐藏
	//二级菜单
	$('.nonconli').hover(function(){
		$(this).find('.noncon').toggle().css('border','1px solid #ccc');
		$(this).find('.noncon').css('border-top','none');
	});
	//二级菜单
	$('.mygou').hover(function(){
		$(this).find('#weixin').toggle().css('border','1px solid #ccc');
		$(this).find('#weixin').css('border-top','none');
	});
	/*nav部分*/
	$('.menu-list li').hover(function(){
		$(this).find('i').css({'opacity':1});
	});
	$(function(){
			//q获取焦点
			$('#q').focus(function(){
				if(q.value=='请输入商品名称,支持拼音搜索'){
					q.value='';
				}

			});
			//q失去焦点
			$('#q').blur(function(){
				if(q.value==""){
					q.value="请输入商品名称,支持拼音搜索";
					
				}
			});
		});
	$(function(){
		$('.menu-list li').each(function(i){

		});
		
	});

});

	

