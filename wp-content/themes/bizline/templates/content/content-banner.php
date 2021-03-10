<?php
/**
 * Template part for displaying inner banner in pages
 *
 * @since 1.0.0
 * 
 * @package Bizline WordPress Theme
 */
?>
<div class="<?php echo esc_attr( Bizline_Helper::get_inner_banner_class() ); ?>" <?php Bizline_Helper::the_header_image(); ?>> 
	<div class="container">
		<?php
			Bizline_Helper::the_inner_banner();
			Bizline_Helper::the_breadcrumb();
		?>
	</div>
</div>
