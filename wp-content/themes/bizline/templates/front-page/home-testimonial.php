<?php
/**
 * Content for home page testimonial section
 *
 * @since 1.0.0
 *
 * @package Bizline WordPress theme
 */

$selected_pages = json_decode( bizline_get( 'testimonial-repeater' ) );

if( bizline_get( 'home-testimonial-status' ) && '' != $selected_pages ) :?>
	<section class="bizline-testimonial-section" style="background: url(<?php echo esc_url( bizline_get( 'home-testimonial-image' ) ); ?>)">
		<div class="container">
			<div class="bizline-testimonial-slider-init">
				<?php foreach ( $selected_pages as $p ) { 
					?>
					<div class="bizline-testimonial-slider-inner">
						<div class="bizline-testimonial-image">
							<img src="<?php echo esc_url( get_the_post_thumbnail_url( $p[ 1 ], 'full' ) ); ?>" alt="testimonials" />
						</div>
						<p><?php echo bizline_excerpt( bizline_get( 'home-testimonial-excerpt-length' ), false, '...', $p[ 1 ] );?></p>
						<div class="testimonial-position testimonials">
							<h3> <span> <?php echo get_the_title( $p[ 1 ] ); ?> </span>
								<?php if ( $p[ 0 ] ): ?>
									 - <?php echo esc_html( $p[ 0 ] );
								endif; ?>
							</h3>
						</div>
					</div> 
				<?php } ?>
			</div>
		</div>
	</section>
<?php endif;
