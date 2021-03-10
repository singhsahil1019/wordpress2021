<?php
/**
 * The template for displaying home page.
 *
 * @since 1.0.0
 *
 * @package Bizline WordPress theme
 */

get_header();
/**
* bizline_homepage hook
*
* homepage slider section  - 10
* homepage quote section - 20
* homepage service section - 30
* homepage testimonial section - 40
* homepage team section - 50
* homepage call to action - 60
* homepage news -70
*/

/**
 * default section order
 *
 * slider
 * quote
 * service
 * features
 * testimonial
 * team
 * cta
 * news
*/
?>
<div id="content">
	<?php Bizline_Theme::get_front_page_templates();
	
	if( bizline_get( 'content-on-frontpage' ) ): ?>
		<div class="container py-5">
			<div class="row">
				<div class="<?php echo esc_attr( Bizline_Theme::is_sidebar_active() ? 'col-md-8 col-lg-8' : 'col-md-12' ); ?> content-order">
					<?php 
						the_post();
						the_content();
					?>
				</div>
				<?php Bizline_Theme::the_sidebar(); ?>
			</div>
		</div>
	<?php endif; ?>
</div>

<?php get_footer(); ?>