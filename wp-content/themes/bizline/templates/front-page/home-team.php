<?php
/**
 * Content for home page team section
 *
 * @since 1.0.0
 *
 * @package Bizline WordPress theme
 */

$page_title = bizline_get( 'home-team-title-page' );
$selected_pages = json_decode( bizline_get( 'team-repeater' ) );

if( bizline_get( 'home-team-status' ) && $page_title ) :?>
	<section class="bizline-team-section">
		<div class="container">
			<?php if( $page_title ): ?>
				<div class="bizline-title-text-center">
					<h2 class="bizline-section-title title-line-before team-title"><?php echo get_the_title( $page_title ); ?></h2>
					<p><?php echo bizline_excerpt( bizline_get( 'excerpt_length' ), false, '...', $page_title ); ?></p>
				</div>
			<?php endif; ?>
			<div class="row">
				<?php
				if( '' != $selected_pages ):
					foreach ( $selected_pages as $p ) : ?>
						<div class="ccol-12 col-md-3 mb-5 mb-md-0">
							<div class="bizline-team-box">
								<div class="bizline-team-image" style="background: url( <?php echo esc_url( get_the_post_thumbnail_url( $p[ 1 ], 'full' ) );?> )" >
								</div>
								<div class="bizline-team-intro">
									<h3>
										<?php echo get_the_title( $p[ 1 ] );
										if ( $p[ 0 ] ): ?>
											<span><?php echo esc_html( $p[ 0 ] ); ?> </span>
										<?php endif; ?>
									</h3>								
								</div>	
								<a href="<?php echo esc_url( get_the_permalink( $p[ 1 ] ) ); ?>" class="team-single-page-link"></a>
							</div>
						</div>
					<?php endforeach;
				endif;?>
			</div>
		</div>
	</section>
<?php endif;

