<?php
/**
 * The template for displaying the footer.
 *
 * @link https://developer.wordpress.org/themes/basics/template-files/#template-partials
 * @since 1.0.0
 *
 * @package Bizline WordPress theme
 */
?>
	<section class="site-footer footer-area">

		<?php do_action( Bizline_Helper::fn_prefix( 'footer' ) ); ?>

	    <!-- footer divider line -->
	    <div class="footer-divider w-100"></div>
	    <?php $author = class_exists( 'Bizline_Pro_Child_Theme' ) ? bizline_get( 'footer-author-show' ) : true;
	    if( bizline_get( 'footer-copyright-text' ) || bizline_get( 'footer-social-menu' ) || $author ): ?>
		    <footer <?php Bizline_Helper::schema_body( 'footer' ); ?> class="footer-bottom-section py-3">
		        <div class="container-fluid">
		             <!-- footer bottom section -->
		             <div class="row justify-content-between">
		             	<?php do_action( Bizline_Helper::fn_prefix( 'copyright' ) ); ?>
		            </div> <!-- footer-bottom -->
		        </div><!-- container -->
		    </footer><!-- footer- copyright -->
		<?php endif ?>
	</section><!-- section -->
	
	<?php do_action( Bizline_Helper::fn_prefix( 'after_footer' ) ); ?>
 </body>
 <?php wp_footer(); ?>
 </html>