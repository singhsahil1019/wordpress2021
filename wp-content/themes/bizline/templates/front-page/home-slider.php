<?php
/**
 * Content for home page slider
 *
 * @since 1.0.0
 *
 * @package Bizline WordPress theme
 */
$selected_pages = json_decode( bizline_get( 'slider-pages' ) );
if( bizline_get( 'home-slider-status' ) ) :
?>
	<section class="bizline-slider-section">
		<div class="bizline-slider-init">
			<?php if( !empty( $selected_pages ) ){
				foreach ( $selected_pages as $p ) { ?>	
					<div class="bizline-slider-content" style="background: url(<?php echo esc_url( get_the_post_thumbnail_url( $p, 'full' ) ); ?>)">
						<div class="container">
							<div class="bizline-slider-content-inner-text">	
								<h2><?php echo get_the_title( $p ); ?></h2>
								<p><?php echo bizline_excerpt( bizline_get( 'home-slider-excerpt-length' ), false, '...', $p ); ?></p>
								<a href="<?php echo esc_url( get_the_permalink( $p ) ); ?>" class="bizline-button-primary"><span id="slider-read-more"><?php echo esc_html( bizline_get( 'home-slider-button-text' ) ); ?></span></a>
							</div>
						</div>
					</div>
				<?php }
			}?>
		</div>
	</section><!-- bizline banner section end -->
<?php endif;

