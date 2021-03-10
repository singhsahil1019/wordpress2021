<?php
/**
 * Content for home page call to action section
 *
 * @since 1.0.0
 *
 * @package Bizline WordPress theme
 */

$selected_page = bizline_get( 'home-cta-page' );
?>
<?php if( bizline_get( 'home-cta-status' ) && $selected_page ): ?>
	<section class="bizline-cta-section" style="background: url(<?php echo esc_url( get_the_post_thumbnail_url( $selected_page, 'full' ) ); ?>)">
		<div class="container">
			<div class="bizline-cat-content">
				<div class="bizline-text-center">
					<h2 class="bizline-section-title"><?php echo get_the_title( $selected_page ); ?></h2>
					<p><?php echo bizline_excerpt( bizline_get( 'home-cta-excerpt-length' ), false, '...', $selected_page ); ?></p>
					<a href="<?php echo esc_url( get_the_permalink( $selected_page ) ); ?>" class="bizline-button-primary">
						<?php echo esc_html( bizline_get( 'home-cta-text' ) ); ?> 							
					</a>

				</div>	
			</div>
		</div>
	</section> <!-- cta section end -->
<?php endif;
