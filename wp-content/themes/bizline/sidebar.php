<?php
/**
 * The sidebar containing the main widget area
 *
 * @link https://developer.wordpress.org/themes/basics/template-files/#template-partials
 *
 * @since 1.0.0
 *
 * @package Bizline WordPress Theme
 */

if ( ! is_active_sidebar( 'bizline_sidebar' ) ) {
	return;
}
?>

<aside id="secondary" class="widget-area">
	<?php dynamic_sidebar( 'bizline_sidebar' ); ?>
</aside><!-- #secondary -->