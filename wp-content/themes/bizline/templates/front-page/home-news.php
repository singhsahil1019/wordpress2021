<?php
/**
 * Content for home page news section
 *
 * @since 1.0.0
 *
 * @package Bizline WordPress theme
 */

$selected_page = bizline_get( 'home-news-title-page' );
$recent_posts = wp_get_recent_posts(array(
    'numberposts' =>  bizline_get( 'home-news_num_post' ), // Number of recent posts thumbnails to display
    'post_status' => 'publish' // Show only the published posts
));

if( $recent_posts && bizline_get( 'home-news-status' ) ) : ?>
	<section class="bizline-news-section">
		<div class="container">
			<?php if( $selected_page ) : ?>
				<div class="bizline-title-text-center">
					<h2 class="bizline-section-title title-line-before news-title"><?php echo get_the_title( $selected_page ) ?></h2>
					<p><?php echo bizline_excerpt( bizline_get( 'excerpt_length' ), false, '...', $selected_page ); ?></p>
				</div>
			<?php endif; ?>
			<div class="row">
				<?php foreach ( $recent_posts as $p) : ?>
					<div class="col-12 col-md-4">
						<div class="bizline-news-content">
							<div class="bizline-news-image">
								<?php $href = has_post_thumbnail( $p[ 'ID' ] ) ? get_the_post_thumbnail_url( $p[ 'ID' ], 'full' ) :  Bizline_Helper::get_theme_uri( 'assets/img/default-image.jpg' ); ?>

								<a href="<?php echo esc_url( get_permalink( $p['ID'] ) ); ?>">
									<img src="<?php echo esc_url( $href ); ?>" alt="news" />
								</a>
							</div>
							
							<div class="news-text">
								<?php set_query_var( 'author_id', $p[ 'post_author' ] );
								get_template_part( 'templates/meta', 'info' ); ?>
								<h3><a href="<?php echo esc_url( get_permalink($p['ID'] ) ); ?>"><?php echo $p['post_title']; ?></a></h3>
								<p><?php echo bizline_excerpt( bizline_get( 'home-news-excerpt-length' ), false, '...', $p['ID'] ); ?></p>
								<a href="<?php echo esc_url( get_permalink( $p['ID'] ) ); ?>" class="bizline-button-primary news-more-btn"><?php esc_html_e( 'Read More', 'bizline' ) ?></a>
							</div>
						</div>
					</div>
				<?php endforeach; ?>
			</div>
			<div class="bizline-btn-on-center">
				<a href="<?php echo get_permalink( get_option( 'page_for_posts' ) ); ?>" class="bizline-button-primary"><?php esc_html_e( 'View More', 'bizline' ) ?>
				</a>
			</div>
		</div>
	</section>
<?php wp_reset_postdata(); 
endif;
