<?php
/**
 * Content for home page service
 *
 * @since 1.0.0
 *
 * @package Bizline WordPress theme
 */
$page_title = bizline_get( 'home-service-title-page' );
$selected_pages = json_decode( bizline_get( 'services-pages' ) );

if( bizline_get( 'home-service-status' ) && $page_title ) :?>
	<section class="bizline-services-section">
		<div class="bizline-services-bg-half" style="background: url(<?php echo esc_url( bizline_get( 'home-service-image' ) ); ?>)"></div>
		<div class="container">
			<div class="row bizline-services-content">
				<div class="col-12 col-md-7">
					<div class="bizline-services-content-inner">
						<?php if( $page_title ): ?>
							<h2 class="bizline-section-title title-line-before service-title">
								<?php echo get_the_title( $page_title ); ?>
							</h2>
							<p>
								<?php echo bizline_excerpt( bizline_get( 'excerpt_length' ), false, '...', $page_title ); ?>
							</p>
						<?php endif; ?>
						<div class="bizline-services-box">
							<?php if( !empty( $selected_pages ) ):
								foreach ( $selected_pages as $p ): ?>
									<div class="bizline-services-box-inner">
										<?php if( has_post_thumbnail( $p ) ): ?>
											<img src="<?php echo esc_url( get_the_post_thumbnail_url( $p, 'full' ) ); ?>" alt="services-image" />
										<?php endif; ?>
										<div class="bizline-services-box-texts">
											<h3>
												<a href="<?php echo esc_url( get_permalink( $p ) ); ?>">
													<?php echo get_the_title( $p ); ?>
													</a>
											</h3>
											<p><?php echo bizline_excerpt( bizline_get( 'home-service-excerpt-length' ), false, '...', $p ); ?></p>
										</div>
									</div>
								<?php endforeach;
							endif;
							if( $page_title ): ?>
								<div class="bizline-more-service-btn">
									<a href="<?php echo esc_url( get_permalink( $page_title ) ); ?>" class="bizline-button-primary"><?php esc_html_e( 'More Services', 'bizline' ); ?></a>
								</div>
							<?php endif; ?>
						</div>
					</div>
				</div>
			</div>
			
		</div>	
	</section>			
<?php endif; ?>		

