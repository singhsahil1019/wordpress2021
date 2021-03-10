<?php
/**
 * Content for home page feature section
 *
 * @since 1.0.0
 *
 * @package Bizline WordPress theme
 */
$page_title = bizline_get( 'home-feature-title-page' );
$selected_pages = json_decode( bizline_get( 'feature-pages' ) );

if( bizline_get( 'home-feature-status' ) && $page_title ) :?>
	<section class="bizline-feature-section">
		<div class="container">
			<?php if( $page_title ): ?>
				<div class="bizline-title-text-center">						
					<h2 class="bizline-section-title title-line-before feature-title d-inline-block">
						<?php echo get_the_title( $page_title ); ?>
					</h2>
					<p><?php echo bizline_excerpt( bizline_get( 'excerpt_length' ), false, '...', $page_title ); ?></p>
				</div>
			<?php endif; ?>
			<div class="row">
				<?php if( !empty( $selected_pages ) ):
					foreach ( $selected_pages as $p ):?>
						<div class="col-md-4 col-12">
							<div class="feature-inner-box">
								<div class="feature-inner-box-image" style="background: url(<?php echo esc_url( get_the_post_thumbnail_url( $p, 'full' ) ); ?>)">									
									
								</div>
								<div class="feature-inner-box-title">
									<h3><?php echo get_the_title( $p ); ?></h3>	
									<p><?php echo bizline_excerpt( bizline_get( 'home-feature-excerpt-length' ), false, '...', $p ); ?></p>									
								</div>
								<a href="<?php echo esc_url( get_permalink( $p ) ); ?>"></a>
							</div>
						</div>
					<?php endforeach; 
				endif;?>
			</div>
			<?php if( $page_title ): ?>
				<div class="bizline-btn-on-center">
					<a href="<?php echo esc_url( get_permalink( $page_title ) ); ?>" class="bizline-button-primary">
						<span id="slider-read-more"><?php esc_html_e( 'Read More', 'bizline' ); ?></span>
					</a>
				</div>
			<?php endif; ?>
		</div>
	</section> <!-- feature section end -->
<?php endif ?>

