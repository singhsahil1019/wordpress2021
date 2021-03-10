<?php
/**
 * Theme copyright template
 *
 * @since 1.0.3
 *
 * @package Bizline WordPress Theme
 */ ?>               
<div class="col-xs-12 col-sm-4">
 	<span id="<?php echo esc_attr( Bizline_Helper::with_prefix( 'copyright' ) ); ?>">
     	<?php
     		$footer_text = bizline_get( 'footer-copyright-text' );
     		echo esc_html( $footer_text );
     	?>
 	</span>	                 	
</div>